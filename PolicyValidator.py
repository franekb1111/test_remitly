import json
import re
from ValidationError_exception import ValidationError

class PolicyValidator:
    def load_policy_from_file(self):
        """Load policy JSON from the specified file."""
        try:
            with open(self.file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            raise ValidationError("The specified file was not found.")
        except json.JSONDecodeError:
            raise ValidationError("Error decoding JSON from the file.")
        except Exception as e:
            raise ValidationError(f"An error occurred while reading the file: {e}")
        
    def validate_policy_structure(self):
        """Validate the structure of the loaded policy JSON."""
        try:
            top_level_keys = {'PolicyName', 'PolicyDocument'}
            actual_keys = set(self.policy.keys())
            if not actual_keys.issubset(top_level_keys):
                extra_keys = actual_keys - top_level_keys
                raise ValidationError(f"Invalid keys found at the top level: {extra_keys}")
            
            policy_name = self.policy.get('PolicyName')
            if not isinstance(policy_name, str):
                raise ValidationError("There must be PolicyName that must be a string.")
            if not (1 <= len(policy_name) <= 128):
                raise ValidationError("PolicyName must be between 1 and 128 characters long.")
            if not re.match(r"[\w+=,.@-]+", policy_name):
                raise ValidationError("PolicyName contains invalid characters.")

            document = self.policy.get('PolicyDocument')
            top_level_keys_doc = {'Version', 'Statement'}
            actual_keys_doc = set(document.keys())
            if not actual_keys_doc.issubset(top_level_keys_doc):
                extra_keys_doc = actual_keys_doc - top_level_keys_doc
                raise ValidationError(f"Invalid keys found at the document level: {extra_keys_doc}")
            if 'Version' not in document:
                raise ValidationError("Missing 'Version' key in PolicyDocument.")
            if 'Statement' not in document:
                raise ValidationError("Missing 'Statement' key in PolicyDocument.")
            if not isinstance(document, dict):
                raise ValidationError("There must be PolicyDocument that must be a dictionary (JSON object).")
            

            statements = document.get('Statement')
            if isinstance(statements, dict):
                statements = [statements]  # Convert single dict to list for uniform processing
            if not isinstance(statements, list) or not statements:
                raise ValidationError("Statement must be a non-empty list or a single dictionary.")

            sids = set()
            allowed_keys = {'Sid', 'Effect', 'Action', 'Principal', 'Resource', 'Condition'}

            for statement in statements:
                if not isinstance(statement, dict):
                    raise ValidationError("Each statement must be a dictionary.")
                if not set(statement.keys()).issubset(allowed_keys):
                    extra_keys = set(statement.keys()) - allowed_keys
                    raise ValidationError(f"Statement contains invalid keys: {extra_keys}")
                sid = statement.get('Sid')
                if sid:
                    if sid in sids:
                        raise ValidationError(f"Duplicate Sid found: {sid}")
                    sids.add(sid)
                if statement.get('Effect') not in ["Allow", "Deny"]:
                    raise ValidationError("Effect must be either 'Allow' or 'Deny'.")
                action = statement.get('Action')
                if isinstance(action, str):
                    action = [action]  # Convert to list for uniform handling below
                if not isinstance(action, list) or not all(isinstance(act, str) for act in action) or action == []:
                    raise ValidationError("Action must be a string or a list of strings and cannot be empty.")
                
            return True
        except ValidationError as e:
            print(f"Validation Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def __init__(self, file_path):
        self.file_path = file_path
        self.policy = self.load_policy_from_file()
        self.is_valid = self.validate_policy_structure()

        
    def validate_resource_list(self):
        """Return False if any statement's Resource field contains only a single '*', True otherwise."""
        document = self.policy.get('PolicyDocument')
        if document:
            statements = document.get('Statement')
            if isinstance(statements, dict):
                statements = [statements] 
            for statement in statements:
                resources = statement.get('Resource')
                if isinstance(resources, list):
                    for resource in resources:
                        if resource == "*":
                            return False
                elif resources == "*":  # Case for single string Resource, not in a list
                    return False
        return True

