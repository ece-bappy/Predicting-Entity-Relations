import json
import xml.etree.ElementTree as ET
import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO
import base64
from flask import Flask, render_template, request
from typing import Dict, Set
import google.generativeai as genai
import os

app = Flask(__name__)

# Configure generative AI (replace with your actual API key)
genai.configure(api_key="AIzaSyB7ch21_gticM3iYGHepb_8zUmzmIEEvJ4")
generation_config = genai.types.GenerationConfig(
    max_output_tokens=2500,
    temperature=0.5,
    top_p=0.95,
    top_k=40,
    presence_penalty=0.0,
)

safety_settings = [
    {
        "category": genai.types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        "threshold": genai.types.HarmBlockThreshold.BLOCK_NONE
    },
    {
        "category": genai.types.HarmCategory.HARM_CATEGORY_HARASSMENT,
        "threshold": genai.types.HarmBlockThreshold.BLOCK_NONE
    },
    {
        "category": genai.types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        "threshold": genai.types.HarmBlockThreshold.BLOCK_NONE
    },
    {
        "category": genai.types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        "threshold": genai.types.HarmBlockThreshold.BLOCK_NONE
    }
]

model = genai.GenerativeModel(
    model_name="gemini-pro",
    generation_config=generation_config,
    safety_settings=safety_settings
)
model = genai.GenerativeModel(model_name="gemini-pro", generation_config=generation_config)

class SecurityTaxonomyMapper:
    def __init__(self, cve_file: str, capec_file: str, cwe_file: str):
        self.cve_file = cve_file
        self.capec_file = capec_file
        self.cwe_file = cwe_file
        self.cwe_details: Dict[str, dict] = {}
        self.capec_details: Dict[str, dict] = {}
        self.cwe_relationships: Dict[str, list] = {}
        self.capec_relationships: Dict[str, list] = {}
        self.cwe_to_capec: Dict[str, Set[str]] = {}
        self.cve_to_cwe: Dict[str, Set[str]] = {}
        self.cve_impact_scores: Dict[str, float] = {}
        self._load_cwe_data()
        self._load_capec_data()
        self._populate_cve_to_cwe_from_cve()
        self._load_cve_impact_scores()

    def _safe_get_text(self, element: ET.Element, path: str, namespace: dict) -> str:
        if element is None:
            return "No information available"
        found_element = element.find(path, namespace)
        if found_element is None or found_element.text is None:
            return "No information available"
        return found_element.text.strip()

    def _load_cwe_data(self):
        try:
            tree = ET.parse(self.cwe_file)
            root = tree.getroot()
            ns = {'ns': 'http://cwe.mitre.org/cwe-7'}
            for weakness in root.findall('.//ns:Weakness', ns):
                try:
                    cwe_id = "CWE-" + weakness.attrib.get('ID', '')
                    if not cwe_id or cwe_id == "CWE-":
                        continue
                    name = weakness.attrib.get('Name', 'No name available')
                    description = self._safe_get_text(weakness, 'ns:Description', ns)
                    self.cwe_details[cwe_id] = {'name': name, 'description': description}
                    relationships = weakness.findall('.//ns:Relationship', ns)
                    self.cwe_relationships.setdefault(cwe_id, [])
                    for relation in relationships:
                        target_id = "CWE-" + relation.find('ns:Target', ns).text if relation.find('ns:Target', ns) is not None else None
                        nature = relation.find('ns:Nature', ns).text if relation.find('ns:Nature', ns) is not None else None
                        if target_id and nature:
                            self.cwe_relationships[cwe_id].append({'target': target_id, 'nature': nature})
                except Exception as e:
                    print(f"Warning: Error processing CWE entry: {e}")
                    continue
        except Exception as e:
            print(f"Error loading CWE file: {e}")
            raise

    def _load_capec_data(self):
        try:
            tree = ET.parse(self.capec_file)
            root = tree.getroot()
            ns = {'ns': 'http://capec.mitre.org/capec-3'}
            attack_patterns = root.findall('.//ns:Attack_Pattern', ns)
            if not attack_patterns:
                print("Warning: No Attack_Pattern elements found in CAPEC file")
            for attack_pattern in attack_patterns:
                try:
                    capec_id = "CAPEC-" + attack_pattern.attrib.get('ID', '')
                    if not capec_id or capec_id == "CAPEC-":
                        continue
                    name = self._safe_get_text(attack_pattern, 'ns:Name', ns)
                    description = self._safe_get_text(attack_pattern, 'ns:Description', ns)
                    self.capec_details[capec_id] = {'name': name, 'description': description}
                    related_cwes = attack_pattern.findall('.//ns:Related_Weakness', ns)
                    for cwe in related_cwes:
                        try:
                            cwe_id = cwe.attrib.get('CWE_ID')
                            if cwe_id:
                                cwe_id = f"CWE-{cwe_id}"
                                if cwe_id not in self.cwe_to_capec:
                                    self.cwe_to_capec[cwe_id] = set()
                                self.cwe_to_capec[cwe_id].add(capec_id)
                        except Exception as e:
                            print(f"Warning: Error processing CAPEC-CWE relationship: {e}")
                            continue
                    related_aps = attack_pattern.findall('.//ns:Related_Attack_Pattern', ns)
                    self.capec_relationships.setdefault(capec_id, [])
                    for related_ap in related_aps:
                        target_id = "CAPEC-" + related_ap.attrib.get('CAPEC_ID', '')
                        nature = related_ap.find('ns:Nature').text if related_ap.find('ns:Nature') is not None else None
                        if target_id and nature:
                            self.capec_relationships[capec_id].append({'target': target_id, 'nature': nature})
                except Exception as e:
                    print(f"Warning: Error processing CAPEC entry: {e}")
                    continue
        except Exception as e:
            print(f"Error loading CAPEC file: {e}")
            raise

    def _populate_cve_to_cwe_from_cve(self):
        try:
            with open(self.cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            for cve_item in cve_data.get('CVE_Items', []):
                cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                if cve_id:
                    problemtype_data = cve_item.get('cve', {}).get('problemtype', {}).get('problemtype_data', [])
                    if problemtype_data and problemtype_data[0].get('description'):
                        for desc in problemtype_data[0]['description']:
                            cwe_value = desc.get('value')
                            if cwe_value and cwe_value.startswith('CWE-'):
                                if cve_id not in self.cve_to_cwe:
                                    self.cve_to_cwe[cve_id] = set()
                                self.cve_to_cwe[cve_id].add(cwe_value)
        except Exception as e:
            print(f"Error loading CVE file to populate CVE-CWE mapping: {e}")

    def _load_cve_impact_scores(self):
        try:
            with open(self.cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            for cve_item in cve_data.get('CVE_Items', []):
                cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                if cve_id:
                    base_metric_v3 = cve_item.get('impact', {}).get('baseMetricV3', {})
                    if base_metric_v3:
                        self.cve_impact_scores[cve_id] = base_metric_v3.get('impactScore', 0.0)
                    else:
                        base_metric_v2 = cve_item.get('impact', {}).get('baseMetricV2', {})
                        if base_metric_v2:
                            self.cve_impact_scores[cve_id] = base_metric_v2.get('impactScore', 0.0)
                        else:
                            self.cve_impact_scores[cve_id] = 0.0
        except Exception as e:
            print(f"Error loading CVE file to populate impact scores: {e}")
    def summarize_text(self, text: str) -> str:
        """Summarizes the *nature* of the given security issue using Google AI Studio's Gemini API."""
        try:
            prompt = f"Provide a brief overview of the technical weakness detailed below:\n{text}"
            response = model.generate_content(prompt)

            if response.prompt_feedback and response.prompt_feedback.block_reason:
                print(f"Error summarizing text: Blocked due to prompt feedback: {response.prompt_feedback.block_reason}")
                return "Summary not available due to content policy (prompt)."

            if response.candidates:
                candidate = response.candidates[0]
                if candidate.finish_reason == 3:
                    print(f"Error summarizing text: Blocked by safety settings. Safety ratings: {candidate.safety_ratings}")
                    return "Summary not available due to content policy (safety settings)."
                elif candidate.content and candidate.content.parts:
                    return "".join([part.text for part in candidate.content.parts])
                else:
                    print(f"Error summarizing text: No text content found in response. Finish reason: {candidate.finish_reason}")
                    return "Summary not available (no content in response)."
            else:
                print("Error summarizing text: No candidates found in the response.")
                return "Summary not available (no response candidates)."

        except Exception as e:
            print(f"Error summarizing text: {e}")
            return "Summary not available due to an error."

    def get_cve_info(self, cve_id: str) -> dict:
        result = {
            'cve_id': cve_id,
            'description': 'No description available',
            'impact_score': 'N/A',
            'exploitability_score': 'N/A',
            'cwes': [],
            'capecs': [],
            'combined_summary': 'No summary available.'
        }
        try:
            with open(self.cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            found_in_cve = False
            for cve_item in cve_data.get('CVE_Items', []):
                if cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == cve_id:
                    found_in_cve = True
                    description_data = cve_item.get('cve', {}).get('description', {}).get('description_data', [])
                    if description_data:
                        result['description'] = description_data[0].get('value', 'No description available')
                    base_metric_v3 = cve_item.get('impact', {}).get('baseMetricV3', {})
                    if base_metric_v3:
                        result['impact_score'] = base_metric_v3.get('impactScore', 'N/A')
                        result['exploitability_score'] = base_metric_v3.get('exploitabilityScore', 'N/A')
                    else:
                        base_metric_v2 = cve_item.get('impact', {}).get('baseMetricV2', {})
                        if base_metric_v2:
                            result['impact_score'] = base_metric_v2.get('impactScore', 'N/A')
                            result['exploitability_score'] = base_metric_v2.get('exploitabilityScore', 'N/A')
                    problemtype_data = cve_item.get('cve', {}).get('problemtype', {}).get('problemtype_data', [])
                    if problemtype_data:
                        for weakness in problemtype_data[0].get('description', []):
                            cwe_id = weakness.get('value', '')
                            if cwe_id.startswith('CWE-') and cwe_id in self.cwe_details:
                                cwe_info = self.cwe_details[cwe_id].copy()
                                cwe_info['id'] = cwe_id
                                result['cwes'].append(cwe_info)
                    break
            if cve_id in self.cve_to_cwe:
                for cwe_id in self.cve_to_cwe[cve_id]:
                    if cwe_id in self.cwe_details:
                        if not any(cwe['id'] == cwe_id for cwe in result['cwes']):
                            cwe_info = self.cwe_details[cwe_id].copy()
                            cwe_info['id'] = cwe_id
                            result['cwes'].append(cwe_info)
            seen_capecs = set()
            for cwe in result['cwes']:
                cwe_id = cwe['id']
                if cwe_id in self.cwe_to_capec:
                    for capec_id in self.cwe_to_capec[cwe_id]:
                        if capec_id in self.capec_details and capec_id not in seen_capecs:
                            capec_info = self.capec_details[capec_id].copy()
                            capec_info['id'] = capec_id
                            result['capecs'].append(capec_info)
                            seen_capecs.add(capec_id)

            # Combine descriptions for summarization
            all_descriptions = [result['description']]
            for cwe in result['cwes']:
                all_descriptions.append(cwe['description'])
            for capec in result['capecs']:
                all_descriptions.append(capec['description'])

            combined_text = "\n".join(all_descriptions)
            result['combined_summary'] = self.summarize_text(combined_text)

        except Exception as e:
            print(f"Error processing data: {e}")
        return result

def create_knowledge_map(cve_id, cwes, capecs, mapper: SecurityTaxonomyMapper):
    G = nx.DiGraph()
    G.add_node(cve_id, type='CVE')
    for cwe in cwes:
        G.add_node(cwe['id'], type='CWE')
        G.add_edge(cve_id, cwe['id'], relation='Identifies')
        if cwe['id'] in mapper.cwe_relationships:
            for relation in mapper.cwe_relationships[cwe['id']]:
                target_cwe_id = relation['target']
                if target_cwe_id in mapper.cwe_details:
                    if relation['nature'] == 'ChildOf':
                        G.add_edge(cwe['id'], target_cwe_id, relation='ChildOf')
                    elif relation['nature'] == 'ParentOf':
                        G.add_edge(target_cwe_id, cwe['id'], relation='ParentOf')
                    elif relation['nature'] == 'CanPrecede':
                        G.add_edge(cwe['id'], target_cwe_id, relation='CanFollow')
                    elif relation['nature'] == 'PeerOf':
                        G.add_edge(cwe['id'], target_cwe_id, relation='Semantic')
    for capec in capecs:
        G.add_node(capec['id'], type='CAPEC')
        for cwe in cwes:
            if capec['id'] in mapper.cwe_to_capec.get(cwe['id'], set()):
                G.add_edge(cwe['id'], capec['id'], relation='AttackOf')
        if capec['id'] in mapper.capec_relationships:
            for relation in mapper.capec_relationships[capec['id']]:
                target_capec_id = relation['target']
                if target_capec_id in mapper.capec_details:
                    if relation['nature'] == 'CanFollow':
                        G.add_edge(capec['id'], target_capec_id, relation='CanFollow')
                    elif relation['nature'] == 'ChildOf':
                        G.add_edge(capec['id'], target_capec_id, relation='ChildOf')
                    elif relation['nature'] == 'ParentOf':
                        G.add_edge(target_capec_id, capec['id'], relation='ParentOf')
    plt.figure(figsize=(12, 12))
    pos = nx.spring_layout(G, k=0.5, iterations=50)
    nx.draw_networkx_edges(G, pos, edge_color='gray', width=1.0, alpha=0.7, arrowsize=10)
    nx.draw_networkx_nodes(G, pos, node_size=[v * 100 for v in dict(G.degree()).values()], node_color='skyblue')
    edge_labels = nx.get_edge_attributes(G, 'relation')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)
    nx.draw_networkx_labels(G, pos, font_size=8)
    img_buf = BytesIO()
    plt.savefig(img_buf, format='png')
    img_buf.seek(0)
    img_base64 = base64.b64encode(img_buf.getvalue()).decode('utf-8')
    plt.close()
    return img_base64

@app.route("/", methods=["GET", "POST"])
def index():
    cve_id = ""
    result = None
    knowledge_map = None
    mapper = SecurityTaxonomyMapper(
        cve_file='nvdcve-1.1-2023.json',
        capec_file='capec_v3.9.xml',
        cwe_file='cwec_v4.16.xml'
    )
    if request.method == "POST":
        cve_id = request.form.get("cve_id")
        result = mapper.get_cve_info(cve_id)
        knowledge_map = create_knowledge_map(cve_id, result['cwes'], result['capecs'], mapper)
    return render_template("index.html", cve_id=cve_id, result=result, knowledge_map=knowledge_map)

@app.route("/cve_with_cwes")
def cve_with_cwes_list():
    mapper = SecurityTaxonomyMapper(
        cve_file='nvdcve-1.1-2023.json',
        capec_file='capec_v3.9.xml',
        cwe_file='cwec_v4.16.xml'
    )
    cves_data = []
    for cve in sorted(mapper.cve_to_cwe.keys()):
        impact_score = mapper.cve_impact_scores.get(cve, 0.0)
        impact_percentage = int((impact_score / 10) * 100) if impact_score is not None else 0
        cves_data.append({'id': cve, 'impact_percentage': impact_percentage, 'impact_score': impact_score})
    return render_template("cve_with_cwes.html", cves_data=cves_data)

if __name__ == "__main__":
    app.run(debug=True)