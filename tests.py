import unittest
import json
import pytest
from unittest.mock import mock_open, patch
from PolicyValidator import PolicyValidator, ValidationError

class TestPolicyValidator(unittest.TestCase):
    def setUp(self):
        self.loader = PolicyValidator(file_path="input_file.json")
        self.validator = PolicyValidator("input_file.json")
        self.validator.policy = {
            "PolicyName": "ValidPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "Stmt1",
                    "Effect": "Allow",
                    "Action": "iam:ListUsers",
                    "Resource": "*"
                }]
            }
        }

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


    @patch("builtins.open", side_effect=Exception("Unexpected error"))
    def test_error_while_reading_file_raises_validation_error(self, mock_open):
        # Testing that a generic exception is caught and a ValidationError is raised with the correct message
        with self.assertRaises(ValidationError) as context:
            self.loader.load_policy_from_file()

        self.assertEqual(str(context.exception), "An error occurred while reading the file: Unexpected error")\

    def test_extra_top_level_keys(self):
        self.validator.policy['ExtraKey'] = 'Value'
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('Invalid keys found at the top level', str(context.exception))
    def test_non_string_policy_name(self):
        self.validator.policy['PolicyName'] = 123
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('There must be PolicyName that must be a string', str(context.exception))

    def test_invalid_policy_name_length(self):
        self.validator.policy['PolicyName'] = ''
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('PolicyName must be between 1 and 128 characters long', str(context.exception))

    def test_invalid_policy_name_characters(self):
        self.validator.policy['PolicyName'] = " \\"
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('PolicyName contains invalid characters', str(context.exception))

    def test_missing_keys_in_document_v(self):
        del self.validator.policy['PolicyDocument']['Version']
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn("Missing 'Version' key", str(context.exception))

    def test_missing_keys_in_document_s(self):
        del self.validator.policy['PolicyDocument']['Statement']
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn("Missing 'Statement' key", str(context.exception))


    def test_non_dict_policy_document(self):
        self.validator.policy['PolicyDocument'] = 'NotADictionary'
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('There must be PolicyDocument that must be a dictionary (JSON object)', str(context.exception))


    def test_ivalid_keys_in_document_lvl(self):
        self.validator.policy['PolicyDocument']['Extra'] = 'Something'
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('Invalid keys found at the document level', str(context.exception))

    def test_invalid_statement_structure(self):
        self.validator.policy['PolicyDocument']['Statement'] = 'NotADictionaryOrList'
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('Statement must be a non-empty list or a single dictionary', str(context.exception))

    def test_no_statements(self):
        self.validator.policy['PolicyDocument']['Statement'] = []
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('Statement must be a non-empty list or a single dictionary', str(context.exception))

    def test_duplicate_sid(self):
        statement = self.validator.policy['PolicyDocument']['Statement'][0]
        self.validator.policy['PolicyDocument']['Statement'].append(statement)  # Duplicate the statement
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn('Duplicate Sid found', str(context.exception))

    def test_invalid_effect(self):
        self.validator.policy['PolicyDocument']['Statement'][0]['Effect'] = 'Maybe'
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn("Effect must be either 'Allow' or 'Deny'", str(context.exception))

    def test_invalid_action_type(self):
        self.validator.policy['PolicyDocument']['Statement'][0]['Action'] = {}
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn("Action must be a string or a list of strings", str(context.exception))

    def test_invalid_action_type_2(self):
        self.validator.policy['PolicyDocument']['Statement'][0]['Action'] = []
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn("Action must be a string or a list of strings and cannot be empty", str(context.exception))

    def test_invalid_action_type_3(self):
        self.validator.policy['PolicyDocument']['Statement'][0]['Action'] = 111
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn("Action must be a string or a list of strings and cannot be empty", str(context.exception))

    def test_statement_invalid_keys(self):
        self.validator.policy['PolicyDocument']['Statement'][0]['Extra'] = 'sth'
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_policy_structure()
        self.assertIn("Statement contains invalid keys", str(context.exception))



if __name__ == "__main__":
    unittest.main()