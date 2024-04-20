from PolicyValidator import PolicyValidator, ValidationError

def run():
    file_path = 'input_file.json' 
    try:
        validator = PolicyValidator(file_path)
        if validator.is_valid:
            print(validator.validate_resource_list())
    except ValidationError as e:
        print(f"Validation failed: {e}")

if __name__ == "__main__":
    run()