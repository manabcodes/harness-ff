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
