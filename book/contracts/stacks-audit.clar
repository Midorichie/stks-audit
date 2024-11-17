# stacks_audit_toolkit/
# │
# ├── src/
# │   ├── __init__.py
# │   ├── analyzer.py
# │   ├── vulnerability_scanner.py
# │   └── utils.py
# │
# ├── tests/
# │   ├── __init__.py
# │   ├── test_analyzer.py
# │   └── test_vulnerabilities.py
# │
# ├── examples/
# │   └── sample_contracts/
# │       └── basic_token.clar
# │
# ├── requirements.txt
# └── README.md

# src/analyzer.py
from typing import Dict, List, Optional
import re

class ClarityAnalyzer:
    """Main class for analyzing Clarity smart contracts"""
    
    def __init__(self):
        self.common_vulnerabilities = {
            'unauthorized_access': r'(?i)(allow|check-auth|auth)',
            'integer_overflow': r'(\+|\-|\*)',
            'unchecked_transfers': r'(stx-transfer\?|contract-call\?)',
            'reentrancy': r'(contract-call\?.*transfer)',
        }
        
    def analyze_contract(self, contract_code: str) -> Dict[str, List[Dict]]:
        """
        Analyzes a Clarity contract for potential vulnerabilities
        
        Args:
            contract_code: String containing the Clarity contract code
            
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        
        # Check for potential vulnerabilities
        for vuln_type, pattern in self.common_vulnerabilities.items():
            matches = re.finditer(pattern, contract_code)
            for match in matches:
                results['vulnerabilities'].append({
                    'type': vuln_type,
                    'line': contract_code.count('\n', 0, match.start()) + 1,
                    'snippet': contract_code[max(0, match.start()-20):match.end()+20],
                    'severity': self._calculate_severity(vuln_type)
                })
                
        # Basic static analysis
        results['info'].extend(self._analyze_contract_structure(contract_code))
        
        return results
    
    def _calculate_severity(self, vuln_type: str) -> str:
        """Calculate vulnerability severity"""
        severity_mapping = {
            'unauthorized_access': 'HIGH',
            'integer_overflow': 'HIGH',
            'unchecked_transfers': 'MEDIUM',
            'reentrancy': 'CRITICAL'
        }
        return severity_mapping.get(vuln_type, 'LOW')
    
    def _analyze_contract_structure(self, contract_code: str) -> List[Dict]:
        """Analyze basic contract structure and patterns"""
        info = []
        
        # Check for public functions
        public_funcs = re.finditer(r'define-public\s*\(([^)]+)\)', contract_code)
        for func in public_funcs:
            info.append({
                'type': 'public_function',
                'name': func.group(1).split()[0],
                'line': contract_code.count('\n', 0, func.start()) + 1
            })
            
        # Check for data vars
        data_vars = re.finditer(r'define-data-var\s*\(([^)]+)\)', contract_code)
        for var in data_vars:
            info.append({
                'type': 'data_var',
                'name': var.group(1).split()[0],
                'line': contract_code.count('\n', 0, var.start()) + 1
            })
            
        return info

# src/vulnerability_scanner.py
class VulnerabilityScanner:
    """Scans for specific vulnerability patterns in Clarity contracts"""
    
    @staticmethod
    def check_reentrancy(contract_code: str) -> List[Dict]:
        """Check for potential reentrancy vulnerabilities"""
        vulnerabilities = []
        
        # Look for patterns that might indicate reentrancy
        transfer_patterns = re.finditer(
            r'contract-call\?\s+[^\s]+\s+transfer',
            contract_code
        )
        
        for match in transfer_patterns:
            # Check if there's state modification after transfer
            code_after_transfer = contract_code[match.end():].strip()
            if re.search(r'define-data-var|map-set|map-delete', code_after_transfer):
                vulnerabilities.append({
                    'type': 'potential_reentrancy',
                    'line': contract_code.count('\n', 0, match.start()) + 1,
                    'description': 'State modification after external call detected'
                })
                
        return vulnerabilities

# src/utils.py
def load_contract(file_path: str) -> str:
    """Load contract from file"""
    with open(file_path, 'r') as f:
        return f.read()

def generate_report(analysis_results: Dict) -> str:
    """Generate human-readable report from analysis results"""
    report = []
    report.append("Smart Contract Audit Report\n")
    report.append("=" * 30 + "\n")
    
    if analysis_results['vulnerabilities']:
        report.append("\nVulnerabilities Found:\n")
        for vuln in analysis_results['vulnerabilities']:
            report.append(f"- {vuln['type']} (Severity: {vuln['severity']})")
            report.append(f"  Line {vuln['line']}: {vuln['snippet']}\n")
    
    if analysis_results['info']:
        report.append("\nContract Structure:\n")
        for info in analysis_results['info']:
            report.append(f"- {info['type']}: {info.get('name', '')} (Line {info['line']})")
    
    return "\n".join(report)