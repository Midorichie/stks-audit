from src.analyzer import ClarityAnalyzer
from src.utils import load_contract, generate_report

# Initialize analyzer
analyzer = ClarityAnalyzer()

# Load and analyze contract
contract_code = load_contract("path/to/contract.clar")
results = analyzer.analyze_contract(contract_code)

# Generate report
report = generate_report(results)
print(report)