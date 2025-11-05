"""
HARNESS-FF: Free Flow Data Restriction Detector for ODRL Policies
Analyzes ODRL policies to detect data localization restrictions related to EU member states
"""

import requests
import json
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, RDFS
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class RestrictionType(Enum):
    """Types of geographic restrictions"""
    SPATIAL_CONSTRAINT = "spatial_constraint"
    LOCATION_CONSTRAINT = "location_constraint"
    TERRITORY_CONSTRAINT = "territory_constraint"


class ComplianceStatus(Enum):
    """Compliance status with EU Free Flow Regulation"""
    COMPLIANT = "compliant"
    POTENTIAL_VIOLATION = "potential_violation"
    REQUIRES_REVIEW = "requires_review"
    ERROR = "error"


@dataclass
class LocalizationRestriction:
    """Represents a detected localization restriction"""
    restriction_type: RestrictionType
    country: str
    country_representation: str
    original_value: str
    policy_element: str
    
    
@dataclass
class EvaluationReport:
    """FFDR Ontology-based evaluation report"""
    policy_uri: str
    compliance_status: ComplianceStatus
    restrictions_found: List[LocalizationRestriction]
    eu_member_states_involved: Set[str]
    analysis_summary: str
    recommendations: List[str]


class EUMemberStateResolver:
    """Resolves various representations of EU member states"""
    
    def __init__(self):
        # EU member states with various representations
        self.member_states = {
            'Austria': {
                'iso': 'AT', 'iso3': 'AUT',
                'wikidata': 'Q40',
                'dbpedia': 'Austria',
                'geonames': '2782113',
                'names': ['austria', 'österreich', 'autriche']
            },
            'Belgium': {
                'iso': 'BE', 'iso3': 'BEL',
                'wikidata': 'Q31',
                'dbpedia': 'Belgium',
                'geonames': '2802361',
                'names': ['belgium', 'belgique', 'belgië', 'belgien']
            },
            'Bulgaria': {
                'iso': 'BG', 'iso3': 'BGR',
                'wikidata': 'Q219',
                'dbpedia': 'Bulgaria',
                'geonames': '732800',
                'names': ['bulgaria', 'bulgarie']
            },
            'Croatia': {
                'iso': 'HR', 'iso3': 'HRV',
                'wikidata': 'Q224',
                'dbpedia': 'Croatia',
                'geonames': '3202326',
                'names': ['croatia', 'croatie', 'hrvatska']
            },
            'Cyprus': {
                'iso': 'CY', 'iso3': 'CYP',
                'wikidata': 'Q229',
                'dbpedia': 'Cyprus',
                'geonames': '146669',
                'names': ['cyprus', 'chypre', 'zypern']
            },
            'Czech Republic': {
                'iso': 'CZ', 'iso3': 'CZE',
                'wikidata': 'Q213',
                'dbpedia': 'Czech_Republic',
                'geonames': '3077311',
                'names': ['czech republic', 'czechia', 'république tchèque', 'tschechien']
            },
            'Denmark': {
                'iso': 'DK', 'iso3': 'DNK',
                'wikidata': 'Q35',
                'dbpedia': 'Denmark',
                'geonames': '2623032',
                'names': ['denmark', 'danemark', 'dänemark']
            },
            'Estonia': {
                'iso': 'EE', 'iso3': 'EST',
                'wikidata': 'Q191',
                'dbpedia': 'Estonia',
                'geonames': '453733',
                'names': ['estonia', 'estonie', 'estland']
            },
            'Finland': {
                'iso': 'FI', 'iso3': 'FIN',
                'wikidata': 'Q33',
                'dbpedia': 'Finland',
                'geonames': '660013',
                'names': ['finland', 'finlande', 'finnland', 'suomi']
            },
            'France': {
                'iso': 'FR', 'iso3': 'FRA',
                'wikidata': 'Q142',
                'dbpedia': 'France',
                'geonames': '3017382',
                'names': ['france', 'frankreich']
            },
            'Germany': {
                'iso': 'DE', 'iso3': 'DEU',
                'wikidata': 'Q183',
                'dbpedia': 'Germany',
                'geonames': '2921044',
                'names': ['germany', 'allemagne', 'deutschland']
            },
            'Greece': {
                'iso': 'GR', 'iso3': 'GRC',
                'wikidata': 'Q41',
                'dbpedia': 'Greece',
                'geonames': '390903',
                'names': ['greece', 'grèce', 'griechenland', 'hellas']
            },
            'Hungary': {
                'iso': 'HU', 'iso3': 'HUN',
                'wikidata': 'Q28',
                'dbpedia': 'Hungary',
                'geonames': '719819',
                'names': ['hungary', 'hongrie', 'ungarn', 'magyarország']
            },
            'Ireland': {
                'iso': 'IE', 'iso3': 'IRL',
                'wikidata': 'Q27',
                'dbpedia': 'Republic_of_Ireland',
                'geonames': '2963597',
                'names': ['ireland', 'irlande', 'irland', 'éire']
            },
            'Italy': {
                'iso': 'IT', 'iso3': 'ITA',
                'wikidata': 'Q38',
                'dbpedia': 'Italy',
                'geonames': '3175395',
                'names': ['italy', 'italie', 'italien', 'italia']
            },
            'Latvia': {
                'iso': 'LV', 'iso3': 'LVA',
                'wikidata': 'Q211',
                'dbpedia': 'Latvia',
                'geonames': '458258',
                'names': ['latvia', 'lettonie', 'lettland']
            },
            'Lithuania': {
                'iso': 'LT', 'iso3': 'LTU',
                'wikidata': 'Q37',
                'dbpedia': 'Lithuania',
                'geonames': '597427',
                'names': ['lithuania', 'lituanie', 'litauen', 'lietuva']
            },
            'Luxembourg': {
                'iso': 'LU', 'iso3': 'LUX',
                'wikidata': 'Q32',
                'dbpedia': 'Luxembourg',
                'geonames': '2960313',
                'names': ['luxembourg', 'luxemburg']
            },
            'Malta': {
                'iso': 'MT', 'iso3': 'MLT',
                'wikidata': 'Q233',
                'dbpedia': 'Malta',
                'geonames': '2562770',
                'names': ['malta', 'malte']
            },
            'Netherlands': {
                'iso': 'NL', 'iso3': 'NLD',
                'wikidata': 'Q55',
                'dbpedia': 'Netherlands',
                'geonames': '2750405',
                'names': ['netherlands', 'pays-bas', 'niederlande', 'holland', 'nederland']
            },
            'Poland': {
                'iso': 'PL', 'iso3': 'POL',
                'wikidata': 'Q36',
                'dbpedia': 'Poland',
                'geonames': '798544',
                'names': ['poland', 'pologne', 'polen', 'polska']
            },
            'Portugal': {
                'iso': 'PT', 'iso3': 'PRT',
                'wikidata': 'Q45',
                'dbpedia': 'Portugal',
                'geonames': '2264397',
                'names': ['portugal']
            },
            'Romania': {
                'iso': 'RO', 'iso3': 'ROU',
                'wikidata': 'Q218',
                'dbpedia': 'Romania',
                'geonames': '798549',
                'names': ['romania', 'roumanie', 'rumänien', 'românia']
            },
            'Slovakia': {
                'iso': 'SK', 'iso3': 'SVK',
                'wikidata': 'Q214',
                'dbpedia': 'Slovakia',
                'geonames': '3057568',
                'names': ['slovakia', 'slovaquie', 'slowakei', 'slovensko']
            },
            'Slovenia': {
                'iso': 'SI', 'iso3': 'SVN',
                'wikidata': 'Q215',
                'dbpedia': 'Slovenia',
                'geonames': '3190538',
                'names': ['slovenia', 'slovénie', 'slowenien', 'slovenija']
            },
            'Spain': {
                'iso': 'ES', 'iso3': 'ESP',
                'wikidata': 'Q29',
                'dbpedia': 'Spain',
                'geonames': '2510769',
                'names': ['spain', 'espagne', 'spanien', 'españa']
            },
            'Sweden': {
                'iso': 'SE', 'iso3': 'SWE',
                'wikidata': 'Q34',
                'dbpedia': 'Sweden',
                'geonames': '2661886',
                'names': ['sweden', 'suède', 'schweden', 'sverige']
            }
        }
        
    def identify_country(self, value: str) -> Tuple[str, str]:
        """
        Identify if a value represents an EU member state
        Returns: (country_name, representation_type) or (None, None)
        """
        value_str = str(value).lower()
        
        for country, data in self.member_states.items():
            # Check ISO codes (exact match)
            if value_str == data['iso'].lower() or value_str == data['iso3'].lower():
                return country, 'ISO_CODE'
            
            # Check Wikidata
            if 'wikidata.org' in value_str and data['wikidata'] in value_str:
                return country, 'WIKIDATA'
            
            # Check DBpedia
            if 'dbpedia.org' in value_str and data['dbpedia'].lower() in value_str:
                return country, 'DBPEDIA'
            
            # Check GeoNames
            if 'geonames.org' in value_str and data['geonames'] in value_str:
                return country, 'GEONAMES'
            
            # Check country names (exact match for literals)
            for name in data['names']:
                if value_str == name or value_str.strip('"\'') == name:
                    return country, 'STRING_LITERAL'
        
        return None, None


class HarnessFF:
    """Main HARNESS-FF analyzer"""
    
    def __init__(self):
        self.resolver = EUMemberStateResolver()
        self.odrl = Namespace("http://www.w3.org/ns/odrl/2/")
        self.graph = None
        
    def fetch_policy(self, url: str) -> Graph:
        """Fetch ODRL policy from URL"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            g = Graph()
            # Try to parse as RDF (turtle, json-ld, xml)
            content_type = response.headers.get('content-type', '')
            
            if 'json' in content_type:
                g.parse(data=response.text, format='json-ld')
            elif 'xml' in content_type or 'rdf' in content_type:
                g.parse(data=response.text, format='xml')
            else:
                # Try turtle format
                g.parse(data=response.text, format='turtle')
            
            self.graph = g
            return g
            
        except Exception as e:
            raise Exception(f"Failed to fetch or parse policy: {str(e)}")
    

    def run_sparql_query(self, query: str):
        """Execute a SPARQL query on the loaded policy graph"""
        if self.graph is None:
            raise Exception("No policy loaded. Call analyze_policy first.")
        
        results = self.graph.query(query)
        return results

    
    def analyze_with_sparql(self, policy_source: str) -> EvaluationReport:
        """Analyze policy using SPARQL queries instead of graph iteration"""
        try:
            # Load the policy
            if policy_source.startswith('http'):
                self.fetch_policy(policy_source)
            else:
                self.graph = Graph()
                self.graph.parse(policy_source)
            
            restrictions = []
            eu_countries = set()
            
            # SPARQL query to find all rightOperand values in constraints
            sparql_query = """
            PREFIX odrl: <http://www.w3.org/ns/odrl/2/>
            
            SELECT ?constraint ?rightOperand
            WHERE {
                ?policy a odrl:Policy .
                ?policy odrl:permission|odrl:prohibition ?rule .
                ?rule odrl:constraint ?constraint .
                ?constraint odrl:rightOperand ?rightOperand .
            }
            """
            
            print(f"\nDEBUG: Running SPARQL query...")
            results = self.graph.query(sparql_query)
            
            for row in results:
                constraint = str(row.constraint)
                right_operand = str(row.rightOperand)
                
                print(f"DEBUG: Found rightOperand via SPARQL: {right_operand}")
                country, repr_type = self.resolver.identify_country(right_operand)
                
                if country:
                    print(f"DEBUG: MATCH! Country: {country}, Type: {repr_type}")
                    restriction = LocalizationRestriction(
                        restriction_type=RestrictionType.SPATIAL_CONSTRAINT,
                        country=country,
                        country_representation=repr_type,
                        original_value=right_operand,
                        policy_element=constraint
                    )
                    restrictions.append(restriction)
                    eu_countries.add(country)
            
            # Generate report
            if len(restrictions) == 0:
                status = ComplianceStatus.COMPLIANT
                summary = "No data localization restrictions related to EU member states detected."
                recommendations = ["Policy appears compliant with Regulation (EU) 2018/1807."]
            else:
                status = ComplianceStatus.POTENTIAL_VIOLATION
                summary = f"Found {len(restrictions)} potential data localization restriction(s) " \
                         f"involving {len(eu_countries)} EU member state(s): {', '.join(sorted(eu_countries))}."
                recommendations = [
                    "Review identified restrictions for compliance with Regulation (EU) 2018/1807.",
                    "Verify if restrictions are justified by public security concerns.",
                    "Consider removing unjustified geographic constraints.",
                    "Consult legal counsel for detailed compliance assessment."
                ]
            
            return EvaluationReport(
                policy_uri=policy_source,
                compliance_status=status,
                restrictions_found=restrictions,
                eu_member_states_involved=eu_countries,
                analysis_summary=summary,
                recommendations=recommendations
            )
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return EvaluationReport(
                policy_uri=policy_source,
                compliance_status=ComplianceStatus.ERROR,
                restrictions_found=[],
                eu_member_states_involved=set(),
                analysis_summary=f"Error analyzing policy: {str(e)}",
                recommendations=["Fix policy format or accessibility issues."]
            )


    def analyze_policy(self, policy_source: str) -> EvaluationReport:
        """
        Analyze ODRL policy for data localization restrictions
        policy_source: URL or file path
        """
        try:
            # Fetch/load the policy
            if policy_source.startswith('http'):
                self.fetch_policy(policy_source)
            else:
                self.graph = Graph()
                self.graph.parse(policy_source)
            
            restrictions = []
            eu_countries = set()
            
            print(f"\nDEBUG: Graph has {len(self.graph)} triples")
            
            # Strategy: Search for ALL objects that might be geographic identifiers
            # First, look specifically for rightOperand values in constraints
            for s, p, o in self.graph:
                pred_str = str(p).lower()
                obj_str = str(o)
                
                country = None
                repr_type = None
                
                # Check if this is a rightOperand in a constraint
                if 'rightoperand' in pred_str or p == self.odrl.rightOperand:
                    print(f"DEBUG: Found rightOperand: {obj_str}")
                    country, repr_type = self.resolver.identify_country(obj_str)
                    
                    if country:
                        print(f"DEBUG: MATCH! Country: {country}, Type: {repr_type}")
                        restriction = LocalizationRestriction(
                            restriction_type=RestrictionType.SPATIAL_CONSTRAINT,
                            country=country,
                            country_representation=repr_type,
                            original_value=obj_str,
                            policy_element=str(s)
                        )
                        restrictions.append(restriction)
                        eu_countries.add(country)
                
                # Also check objects directly for any triple (if not already found)
                if country is None:
                    country, repr_type = self.resolver.identify_country(obj_str)
                    if country and country not in eu_countries:
                        print(f"DEBUG: Found country in general search: {country}, Type: {repr_type}")
                        restriction = LocalizationRestriction(
                            restriction_type=RestrictionType.LOCATION_CONSTRAINT,
                            country=country,
                            country_representation=repr_type,
                            original_value=obj_str,
                            policy_element=str(s)
                        )
                        restrictions.append(restriction)
                        eu_countries.add(country)
            
            # Determine compliance status
            if len(restrictions) == 0:
                status = ComplianceStatus.COMPLIANT
                summary = "No data localization restrictions related to EU member states detected."
                recommendations = ["Policy appears compliant with Regulation (EU) 2018/1807."]
            else:
                status = ComplianceStatus.POTENTIAL_VIOLATION
                summary = f"Found {len(restrictions)} potential data localization restriction(s) " \
                         f"involving {len(eu_countries)} EU member state(s): {', '.join(sorted(eu_countries))}."
                recommendations = [
                    "Review identified restrictions for compliance with Regulation (EU) 2018/1807.",
                    "Verify if restrictions are justified by public security concerns.",
                    "Consider removing unjustified geographic constraints.",
                    "Consult legal counsel for detailed compliance assessment."
                ]
            
            return EvaluationReport(
                policy_uri=policy_source,
                compliance_status=status,
                restrictions_found=restrictions,
                eu_member_states_involved=eu_countries,
                analysis_summary=summary,
                recommendations=recommendations
            )
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return EvaluationReport(
                policy_uri=policy_source,
                compliance_status=ComplianceStatus.ERROR,
                restrictions_found=[],
                eu_member_states_involved=set(),
                analysis_summary=f"Error analyzing policy: {str(e)}",
                recommendations=["Fix policy format or accessibility issues."]
            )
    
    def generate_report(self, evaluation: EvaluationReport) -> str:
        """Generate human-readable report"""
        report = []
        report.append("="*70)
        report.append("HARNESS-FF: Free Flow Data Restriction Analysis Report")
        report.append("="*70)
        report.append(f"\nPolicy URI: {evaluation.policy_uri}")
        report.append(f"Compliance Status: {evaluation.compliance_status.value.upper()}")
        report.append(f"\n{evaluation.analysis_summary}")
        
        if evaluation.restrictions_found:
            report.append(f"\n{'='*70}")
            report.append("DETECTED RESTRICTIONS:")
            report.append("="*70)
            for i, restriction in enumerate(evaluation.restrictions_found, 1):
                report.append(f"\n[{i}] Restriction Type: {restriction.restriction_type.value}")
                report.append(f"    Country: {restriction.country}")
                report.append(f"    Representation: {restriction.country_representation}")
                report.append(f"    Original Value: {restriction.original_value}")
                report.append(f"    Policy Element: {restriction.policy_element}")
        
        report.append(f"\n{'='*70}")
        report.append("RECOMMENDATIONS:")
        report.append("="*70)
        for i, rec in enumerate(evaluation.recommendations, 1):
            report.append(f"{i}. {rec}")
        
        report.append("\n" + "="*70)
        report.append("Analysis completed by HARNESS-FF")
        report.append("Regulation (EU) 2018/1807 Compliance Checker")
        report.append("="*70)
        
        return "\n".join(report)


# Example usage
if __name__ == "__main__":
    harness = HarnessFF()
    
    # Example: Analyze a policy from URL
    policy_url = "https://example.org/odrl-policy.ttl"
    
    print("HARNESS-FF: Analyzing ODRL Policy for Data Localization Restrictions\n")
    
    # For demonstration, let's create a sample policy
    sample_policy = """
    @prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    @prefix ex: <http://example.org/> .
    
    ex:policy1 a odrl:Policy ;
        odrl:permission [
            odrl:target ex:dataset1 ;
            odrl:action odrl:read ;
            odrl:constraint [
                odrl:leftOperand odrl:spatial ;
                odrl:operator odrl:eq ;
                odrl:rightOperand <https://www.wikidata.org/resource/Q183>
            ]
        ] .
    """
    
    # Save sample policy
    with open('/tmp/sample_policy.ttl', 'w') as f:
        f.write(sample_policy)
    
    # Analyze the policy
    evaluation = harness.analyze_policy('/tmp/sample_policy.ttl')
    
    # Generate and print report
    report = harness.generate_report(evaluation)
    print(report)
    
    # Also output as JSON for machine processing
    print("\n\nJSON Output (FFDR Ontology representation):")
    json_output = {
        'policy_uri': evaluation.policy_uri,
        'compliance_status': evaluation.compliance_status.value,
        'summary': evaluation.analysis_summary,
        'eu_member_states_involved': list(evaluation.eu_member_states_involved),
        'restrictions': [
            {
                'type': r.restriction_type.value,
                'country': r.country,
                'representation': r.country_representation,
                'value': r.original_value
            } for r in evaluation.restrictions_found
        ],
        'recommendations': evaluation.recommendations
    }
    print(json.dumps(json_output, indent=2))
