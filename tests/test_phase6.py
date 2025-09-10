"""
Phase 6 Testing Suite - Comprehensive Email Analysis Testing

This module runs comprehensive tests on the Phish-Net email analyzer to validate:
- Detection accuracy across different email types
- Scoring consistency and reliability  
- Performance metrics and response times
- Edge case handling
- User experience workflows
"""

import sys
import os
import time
import json
import statistics
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from sample_emails import ALL_EMAIL_SAMPLES, validate_test_results, get_samples_by_category
    from email_processor import EmailProcessor
    from llm_service import OllamaService
    from risk_assessment import RiskAssessment
    from error_handling import error_handler
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the tests directory and all dependencies are installed")
    sys.exit(1)


class PhishNetTestSuite:
    """Comprehensive test suite for Phase 6 validation"""
    
    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "phi4-mini"):
        self.ollama_url = ollama_url
        self.model = model
        self.email_processor = EmailProcessor()
        self.llm_service = OllamaService(ollama_url, model)
        self.risk_assessor = RiskAssessment()
        self.test_results = {
            "accuracy_tests": [],
            "performance_tests": [],
            "edge_case_tests": [],
            "error_handling_tests": [],
            "summary": {}
        }
        
    def run_all_tests(self, quick_mode: bool = False) -> Dict:
        """Run complete test suite"""
        print("🧪 Starting Phase 6 Comprehensive Testing Suite")
        print("=" * 60)
        
        start_time = time.time()
        
        # Test 1: System Health Check
        print("\n🔧 1. System Health Check")
        health_status = self._test_system_health()
        
        if health_status["overall_status"] != "healthy":
            print("❌ System health check failed. Please resolve issues before testing.")
            return {"error": "System unhealthy", "health": health_status}
        
        # Test 2: Accuracy Testing
        print("\n🎯 2. Detection Accuracy Testing")
        accuracy_results = self._test_detection_accuracy(quick_mode)
        
        # Test 3: Performance Testing  
        print("\n⚡ 3. Performance Testing")
        performance_results = self._test_performance(quick_mode)
        
        # Test 4: Edge Case Testing
        print("\n🔍 4. Edge Case Testing")
        edge_case_results = self._test_edge_cases()
        
        # Test 5: Error Handling Testing
        print("\n🛡️ 5. Error Handling Testing") 
        error_handling_results = self._test_error_handling()
        
        # Generate Summary
        total_time = time.time() - start_time
        summary = self._generate_test_summary(total_time)
        
        self.test_results["summary"] = summary
        
        print(f"\n✅ Testing Complete in {total_time:.2f} seconds")
        self._print_summary(summary)
        
        return self.test_results
    
    def _test_system_health(self) -> Dict:
        """Test system health and readiness"""
        print("   Checking Ollama connection...")
        connection = self.llm_service.test_connection()
        
        print("   Checking system health...")
        health = error_handler.check_system_health()
        
        if health["overall_status"] == "healthy":
            print("   ✅ System healthy and ready")
        else:
            print(f"   ❌ System status: {health['overall_status']}")
            for error in health.get("errors", []):
                print(f"      {error}")
        
        return health
    
    def _test_detection_accuracy(self, quick_mode: bool = False) -> Dict:
        """Test detection accuracy across all email categories"""
        accuracy_results = {
            "total_tests": 0,
            "passed_tests": 0,
            "category_results": {},
            "detailed_results": []
        }
        
        # Select samples for testing
        samples_to_test = ALL_EMAIL_SAMPLES
        if quick_mode:
            # Quick mode: test 2 samples per category
            samples_to_test = {}
            for category in ["legitimate", "suspicious", "phishing", "edge_case"]:
                category_samples = get_samples_by_category(category)
                for i, (key, data) in enumerate(category_samples.items()):
                    if i < 2:  # Take first 2 samples per category
                        samples_to_test[key] = data
        
        print(f"   Testing {len(samples_to_test)} email samples...")
        
        for email_key, email_data in samples_to_test.items():
            print(f"   📧 Testing: {email_data['description']}")
            
            start_time = time.time()
            
            # Process email
            processed_data = self.email_processor.process_email(
                email_data["content"], 
                is_file_content=False
            )
            
            # Analyze with LLM
            analysis_result = self.llm_service.analyze_email(processed_data)
            
            analysis_time = time.time() - start_time
            
            # Extract risk score
            risk_score = 5  # Default fallback
            if analysis_result.get("success") and "risk_score" in analysis_result:
                risk_score = analysis_result["risk_score"]
            elif analysis_result.get("risk_assessment", {}).get("risk_score"):
                risk_score = analysis_result["risk_assessment"]["risk_score"]
            
            # Validate results
            validation = validate_test_results(email_key, risk_score)
            validation["analysis_time"] = analysis_time
            validation["llm_success"] = analysis_result.get("success", False)
            
            accuracy_results["detailed_results"].append(validation)
            accuracy_results["total_tests"] += 1
            
            if validation["passed"]:
                accuracy_results["passed_tests"] += 1
                print(f"      ✅ PASS - Risk: {risk_score} (expected: {validation['expected_range']})")
            else:
                print(f"      ❌ FAIL - Risk: {risk_score} (expected: {validation['expected_range']})")
            
            # Category tracking
            category = validation["category"]
            if category not in accuracy_results["category_results"]:
                accuracy_results["category_results"][category] = {"total": 0, "passed": 0}
            
            accuracy_results["category_results"][category]["total"] += 1
            if validation["passed"]:
                accuracy_results["category_results"][category]["passed"] += 1
        
        # Calculate accuracy percentage
        accuracy_results["accuracy_percentage"] = (
            accuracy_results["passed_tests"] / accuracy_results["total_tests"] * 100
            if accuracy_results["total_tests"] > 0 else 0
        )
        
        self.test_results["accuracy_tests"] = accuracy_results
        
        print(f"   📊 Overall Accuracy: {accuracy_results['accuracy_percentage']:.1f}%")
        
        return accuracy_results
    
    def _test_performance(self, quick_mode: bool = False) -> Dict:
        """Test system performance metrics"""
        performance_results = {
            "response_times": [],
            "memory_usage": [],
            "concurrent_tests": {},
            "large_email_test": {}
        }
        
        # Test response times with various email sizes
        test_emails = ["corporate_newsletter", "banking_phish", "very_short"]
        if not quick_mode:
            test_emails = list(ALL_EMAIL_SAMPLES.keys())[:5]
        
        print(f"   Testing response times for {len(test_emails)} emails...")
        
        for email_key in test_emails:
            email_data = ALL_EMAIL_SAMPLES[email_key]
            
            start_time = time.time()
            
            processed_data = self.email_processor.process_email(
                email_data["content"], 
                is_file_content=False
            )
            analysis_result = self.llm_service.analyze_email(processed_data)
            
            response_time = time.time() - start_time
            performance_results["response_times"].append({
                "email": email_key,
                "time": response_time,
                "content_length": len(email_data["content"]),
                "success": analysis_result.get("success", False)
            })
            
            print(f"      {email_key}: {response_time:.2f}s")
        
        # Calculate performance stats
        times = [r["time"] for r in performance_results["response_times"]]
        if times:
            performance_results["avg_response_time"] = statistics.mean(times)
            performance_results["max_response_time"] = max(times)
            performance_results["min_response_time"] = min(times)
        
        # Test large email handling
        if not quick_mode:
            print("   Testing large email handling...")
            large_email = self._create_large_email()
            start_time = time.time()
            
            try:
                processed_data = self.email_processor.process_email(large_email, is_file_content=False)
                analysis_result = self.llm_service.analyze_email(processed_data)
                large_time = time.time() - start_time
                
                performance_results["large_email_test"] = {
                    "success": True,
                    "time": large_time,
                    "content_length": len(large_email)
                }
                print(f"      Large email ({len(large_email)} chars): {large_time:.2f}s")
            except Exception as e:
                performance_results["large_email_test"] = {
                    "success": False,
                    "error": str(e),
                    "content_length": len(large_email)
                }
                print(f"      Large email failed: {str(e)}")
        
        self.test_results["performance_tests"] = performance_results
        
        avg_time = performance_results.get("avg_response_time", 0)
        print(f"   📊 Average Response Time: {avg_time:.2f}s")
        
        return performance_results
    
    def _test_edge_cases(self) -> Dict:
        """Test edge cases and unusual email formats"""
        edge_results = {
            "tests": [],
            "passed": 0,
            "total": 0
        }
        
        edge_cases = get_samples_by_category("edge_case")
        
        print(f"   Testing {len(edge_cases)} edge cases...")
        
        for email_key, email_data in edge_cases.items():
            print(f"   🔍 Testing: {email_data['description']}")
            
            try:
                processed_data = self.email_processor.process_email(
                    email_data["content"], 
                    is_file_content=False
                )
                analysis_result = self.llm_service.analyze_email(processed_data)
                
                test_result = {
                    "email_key": email_key,
                    "description": email_data["description"],
                    "success": analysis_result.get("success", False),
                    "error": None
                }
                
                if test_result["success"]:
                    print("      ✅ Handled successfully")
                    edge_results["passed"] += 1
                else:
                    print("      ❌ Failed to process")
                
            except Exception as e:
                test_result = {
                    "email_key": email_key,
                    "description": email_data["description"], 
                    "success": False,
                    "error": str(e)
                }
                print(f"      ❌ Exception: {str(e)}")
            
            edge_results["tests"].append(test_result)
            edge_results["total"] += 1
        
        self.test_results["edge_case_tests"] = edge_results
        
        success_rate = edge_results["passed"] / edge_results["total"] * 100 if edge_results["total"] > 0 else 0
        print(f"   📊 Edge Case Success Rate: {success_rate:.1f}%")
        
        return edge_results
    
    def _test_error_handling(self) -> Dict:
        """Test error handling scenarios"""
        error_tests = {
            "connection_test": None,
            "invalid_email_test": None,
            "malformed_response_test": None
        }
        
        print("   Testing error scenarios...")
        
        # Test 1: Invalid email content
        print("   🔧 Testing invalid email handling...")
        try:
            invalid_emails = ["", "not an email", "From: \nTo: \nSubject: \n\n"]
            
            for invalid_content in invalid_emails:
                processed_data = self.email_processor.process_email(invalid_content, is_file_content=False)
                # Should handle gracefully without crashing
            
            error_tests["invalid_email_test"] = {"success": True, "error": None}
            print("      ✅ Invalid email handling works")
            
        except Exception as e:
            error_tests["invalid_email_test"] = {"success": False, "error": str(e)}
            print(f"      ❌ Invalid email handling failed: {str(e)}")
        
        # Test 2: Connection error simulation (using wrong URL)
        print("   🔧 Testing connection error handling...")
        try:
            bad_service = OllamaService("http://nonexistent:11434", self.model)
            connection_result = bad_service.test_connection()
            
            if not connection_result.get("connected"):
                error_tests["connection_test"] = {"success": True, "handled_gracefully": True}
                print("      ✅ Connection errors handled gracefully")
            else:
                error_tests["connection_test"] = {"success": False, "unexpected_connection": True}
                print("      ❌ Unexpected connection success")
                
        except Exception as e:
            error_tests["connection_test"] = {"success": False, "error": str(e)}
            print(f"      ❌ Connection test failed: {str(e)}")
        
        self.test_results["error_handling_tests"] = error_tests
        
        return error_tests
    
    def _create_large_email(self) -> str:
        """Create a large email for testing performance"""
        base_email = """From: newsletter@company.com
To: user@example.com  
Subject: Large Newsletter - Performance Test
Date: Fri, 28 Sep 2025 12:00:00 +0000

This is a performance test email with very long content.

"""
        # Add repetitive content to make it large
        content_block = """
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor 
incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis 
nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore.

Visit our website: https://example-company.com/newsletter
Follow us on social media: https://twitter.com/company
Read our blog: https://company.com/blog

""" * 100  # Repeat 100 times to make it large
        
        return base_email + content_block
    
    def _generate_test_summary(self, total_time: float) -> Dict:
        """Generate comprehensive test summary"""
        accuracy = self.test_results.get("accuracy_tests", {})
        performance = self.test_results.get("performance_tests", {})
        edge_cases = self.test_results.get("edge_case_tests", {})
        error_handling = self.test_results.get("error_handling_tests", {})
        
        summary = {
            "test_timestamp": datetime.now().isoformat(),
            "total_execution_time": total_time,
            "ollama_url": self.ollama_url,
            "model": self.model,
            "overall_status": "PASS",
            "metrics": {
                "detection_accuracy": accuracy.get("accuracy_percentage", 0),
                "avg_response_time": performance.get("avg_response_time", 0),
                "edge_case_success": (edge_cases.get("passed", 0) / edge_cases.get("total", 1) * 100),
                "tests_completed": accuracy.get("total_tests", 0) + edge_cases.get("total", 0)
            },
            "recommendations": []
        }
        
        # Determine overall status and recommendations
        if summary["metrics"]["detection_accuracy"] < 70:
            summary["overall_status"] = "FAIL"
            summary["recommendations"].append("Detection accuracy below 70% - review model prompts and training")
        
        if summary["metrics"]["avg_response_time"] > 10:
            summary["recommendations"].append("Average response time > 10s - optimize model or increase timeout")
        
        if summary["metrics"]["edge_case_success"] < 80:
            summary["recommendations"].append("Edge case handling below 80% - improve error handling")
        
        if not summary["recommendations"]:
            summary["recommendations"].append("All tests passing - system ready for production")
        
        return summary
    
    def _print_summary(self, summary: Dict):
        """Print formatted test summary"""
        print("\n" + "=" * 60)
        print("📊 PHASE 6 TEST SUMMARY")
        print("=" * 60)
        print(f"Overall Status: {'✅ PASS' if summary['overall_status'] == 'PASS' else '❌ FAIL'}")
        print(f"Total Time: {summary['total_execution_time']:.2f}s")
        print()
        print("Key Metrics:")
        print(f"  • Detection Accuracy: {summary['metrics']['detection_accuracy']:.1f}%")
        print(f"  • Average Response Time: {summary['metrics']['avg_response_time']:.2f}s")
        print(f"  • Edge Case Success: {summary['metrics']['edge_case_success']:.1f}%")
        print(f"  • Tests Completed: {summary['metrics']['tests_completed']}")
        print()
        print("Recommendations:")
        for rec in summary["recommendations"]:
            print(f"  • {rec}")
        print("=" * 60)
    
    def save_results(self, filename: str = None):
        """Save test results to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"phase6_test_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        
        print(f"📄 Test results saved to: {filename}")


def main():
    """Main test runner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run Phase 6 Testing Suite')
    parser.add_argument('--quick', action='store_true', help='Run quick test mode')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama URL')
    parser.add_argument('--model', default='phi4-mini', help='Model name')
    parser.add_argument('--save', help='Save results to file')
    
    args = parser.parse_args()
    
    # Initialize test suite
    suite = PhishNetTestSuite(args.ollama_url, args.model)
    
    # Run tests
    results = suite.run_all_tests(args.quick)
    
    # Save results if requested
    if args.save:
        suite.save_results(args.save)
    
    # Exit with appropriate code
    overall_status = results.get("summary", {}).get("overall_status", "FAIL")
    exit_code = 0 if overall_status == "PASS" else 1
    exit(exit_code)


if __name__ == "__main__":
    main()