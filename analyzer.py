from src.analyzer import ClarityAnalyzer

# Initialize analyzer with custom config
analyzer = ClarityAnalyzer({
    'deep_analysis': True,
    'gas_analysis': True,
    'type_checking': True
})

# Analyze contract with deep analysis
contract_code = load_contract("path/to/contract.clar")
results = await analyzer.analyze_contract(contract_code, deep_analysis=True)

# Access new analysis features
print("Gas Analysis:", results['gas_analysis'])
print("Type Analysis:", results['type_analysis'])
print("Optimization Suggestions:", results['optimization_suggestions'])