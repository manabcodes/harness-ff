from harness_ff2 import HarnessFF
import sys

harness = HarnessFF()

for policy_file in ['policy1.ttl', 
                    'policy2.ttl', 
                    'policy3.ttl',
		    'policy4.ttl',
		   ]:
    print('\n' + '='*70)
    print(f'Testing: {policy_file}')
    print('='*70)
    evaluation = harness.analyze_policy(policy_file)
    print(harness.generate_report(evaluation))

# Test SPARQL functionality
# harness = HarnessFF()

# Option 1: Use the SPARQL-based analyzer
evaluation = harness.analyze_with_sparql('policy1.ttl')
print(harness.generate_report(evaluation))

# Option 2: Run custom SPARQL queries
harness.analyze_policy('policy1.ttl')  # Load the policy first
custom_query = """
PREFIX odrl: <http://www.w3.org/ns/odrl/2/>
SELECT ?s ?p ?o
WHERE {
    ?s ?p ?o .
    FILTER(contains(str(?o), "Germany") || contains(str(?o), "DE"))
}
"""
results = harness.run_sparql_query(custom_query)
for row in results:
    print(f"Found: {row}")