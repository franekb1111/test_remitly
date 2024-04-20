import unittest
from unittest.mock import mock_open, patch
from PolicyValidator import PolicyValidator, ValidationError

class TestPolicyValidator(unittest.TestCase):
    def test_file_not_found(self):
        with patch('builtins.open', mock_open()) as mocked_file:
            mocked_file.side_effect = FileNotFoundError
            with self.assertRaises(ValidationError) as context:
                validator = PolicyValidator("nonexistent_file.json")
            self.assertEqual(str(context.exception), "The specified file was not found.")

    def test_invalid_json(self):
        mock_json = '{"PolicyName": "ExamplePolicy", "PolicyDocument": {"Version": "2012-10-17" "Statement": {}}'
        with patch('builtins.open', mock_open(read_data=mock_json)):
            with self.assertRaises(ValidationError) as context:
                validator = PolicyValidator("bad_json.json")
            self.assertIn("Error decoding JSON from the file", str(context.exception))

    def test_valid_json_file(self):
        # Mock JSON content that represents a correctly structured policy
        mock_json = '''
        {
            "PolicyName": "ValidPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Stmt1",
                        "Effect": "Allow",
                        "Action": ["service:action1", "service:action2"],
                        "Resource": ["arn:aws:example:123456789012:*"]
                    },
                    {
                        "Sid": "Stmt2",
                        "Effect": "Deny",
                        "Action": "service:action3",
                        "Resource": "arn:aws:example:123456789012:specific/resource"
                    }
                ]
            }
        }
        '''
        with patch('builtins.open', mock_open(read_data=mock_json)), patch('json.load') as mock_json_load:
            # Mock the json.load to return the expected dictionary directly (avoids file handling complexities)
            mock_json_load.return_value = {
                "PolicyName": "ValidPolicy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "Stmt1",
                            "Effect": "Allow",
                            "Action": ["service:action1", "service:action2"],
                            "Resource": ["arn:aws:example:123456789012:*"]
                        },
                        {
                            "Sid": "Stmt2",
                            "Effect": "Deny",
                            "Action": "service:action3",
                            "Resource": "arn:aws:example:123456789012:specific/resource"
                        }
                    ]
                }
            }
            # Instantiate the PolicyValidator with a mock file path
            validator = PolicyValidator("valid_policy.json")

            # Check if the loaded and validated policy is marked as valid
            self.assertTrue(validator.is_valid, "The policy should be valid and correctly structured.")

if __name__ == "__main__":
    unittest.main()