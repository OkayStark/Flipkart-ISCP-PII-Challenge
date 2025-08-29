#!/usr/bin/env python3
"""
Personal Data Detection and Redaction Tool
Developed for Flixkart ISCP Security Challenge

This tool scans JSON records in CSV format to identify and mask
sensitive personal information according to data protection guidelines.
Handles both individual PII elements and combinations that create PII.
"""

import sys
import csv
import json
import re
from typing import Dict, Set, Any

# Pattern definitions for various PII types
PHONE_REGEX = re.compile(r'\b(\d{10})\b')
AADHAAR_REGEX = re.compile(r'\b(\d{4}\s?\d{4}\s?\d{4})\b')
PASSPORT_REGEX = re.compile(r'\b([A-PR-WYa-pr-wy][1-9]\d{6})\b')
UPI_REGEX = re.compile(r'\b[\w.-]+@[\w.-]+\b')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
ADDRESS_REGEX = re.compile(r'\d+\s+\w+.*\d{6}')


class DataRedactor:
    """Handles redaction of different PII types with appropriate masking patterns"""
    
    @staticmethod
    def redact_phone(phone_number):
        """Redacts phone number while preserving first and last two digits"""
        return phone_number[:2] + 'XXXXXX' + phone_number[-2:]
    
    @staticmethod
    def redact_aadhaar(aadhaar_number):
        """Redacts Aadhaar number while preserving first and last two digits"""
        cleaned = aadhaar_number.replace(' ', '')
        return cleaned[:2] + 'XXXXXXXX' + cleaned[-2:]
    
    @staticmethod
    def redact_passport(passport_number):
        """Redacts passport number while preserving first character"""
        return passport_number[0] + 'XXXXXXX'
    
    @staticmethod
    def redact_email(email_address):
        """Redacts email while keeping domain and partial username visible"""
        username, domain = email_address.split('@')
        if len(username) > 2:
            return username[:2] + 'XXX' + '@' + domain
        return 'X' * len(username) + '@' + domain
    
    @staticmethod
    def redact_name(full_name):
        """Redacts name while preserving first letter of each word"""
        words = full_name.split()
        redacted_words = []
        for word in words:
            if len(word) > 1:
                redacted_words.append(word[0] + 'XXX')
            else:
                redacted_words.append(word)
        return ' '.join(redacted_words)
    
    @staticmethod
    def redact_upi(upi_identifier):
        """Redacts UPI ID while keeping domain visible"""
        username, domain = upi_identifier.split('@')
        if len(username) > 2:
            return username[:2] + 'XXX@' + domain
        return 'X' * len(username) + '@' + domain
    
    @staticmethod
    def redact_address(address_text):
        """Completely redacts address information"""
        return '[REDACTED_PII]'
    
    @staticmethod
    def redact_ip_address(ip_address):
        """Redacts IP address while preserving first and last octets"""
        octets = ip_address.split('.')
        return octets[0] + '.XXX.XXX.' + octets[-1]


class PIIValidator:
    """Validates different types of PII data"""
    
    @staticmethod
    def is_valid_full_name(name_text):
        """Checks if text represents a complete name (first and last)"""
        return len(name_text.split()) >= 2
    
    @staticmethod
    def is_valid_address(address_text):
        """Checks if text matches address pattern with PIN code"""
        return bool(ADDRESS_REGEX.search(address_text))


class PIIDetectionEngine:
    """Main engine for detecting and processing PII in data records"""
    
    def __init__(self):
        self.redactor = DataRedactor()
        self.validator = PIIValidator()
    
    def analyze_record(self, record_data):
        """
        Analyzes a single record for PII and returns redacted version
        Returns tuple: (redacted_record, is_pii_present)
        """
        redacted_data = record_data.copy()
        pii_detected = False
        combination_markers = set()
        
        # Process standalone PII types (always considered sensitive)
        pii_detected |= self._process_standalone_pii(record_data, redacted_data)
        
        # Identify combinatorial PII elements
        self._identify_combination_elements(record_data, redacted_data, combination_markers)
        
        # Apply combinatorial logic (2+ elements = PII)
        # Special case: first_name + last_name is always PII
        has_first_last_name = 'first_name' in record_data and 'last_name' in record_data
        if len(combination_markers) >= 2 or (has_first_last_name and 'name' in combination_markers):
            pii_detected = True
        elif len(combination_markers) == 1 and not pii_detected:
            # Restore non-PII data if only single combination element (except first+last name)
            if not has_first_last_name:
                self._restore_non_pii_data(record_data, redacted_data, combination_markers)
        
        # Scan text fields for embedded PII
        pii_detected |= self._scan_text_fields(record_data, redacted_data)
        
        return redacted_data, pii_detected
    
    def _process_standalone_pii(self, original_data, redacted_data):
        """Process data types that are always considered PII"""
        pii_found = False
        
        # Phone number processing
        if 'phone' in original_data:
            phone_str = str(original_data['phone'])
            if PHONE_REGEX.fullmatch(phone_str) and phone_str[0] in '6789':
                redacted_data['phone'] = self.redactor.redact_phone(phone_str)
                pii_found = True
        
        # Aadhaar number processing
        if 'aadhar' in original_data:
            aadhaar_str = str(original_data['aadhar']).replace(' ', '')
            if AADHAAR_REGEX.fullmatch(aadhaar_str) and not aadhaar_str.startswith('0'):
                redacted_data['aadhar'] = self.redactor.redact_aadhaar(str(original_data['aadhar']))
                pii_found = True
        
        # Passport number processing
        if 'passport' in original_data:
            passport_str = str(original_data['passport'])
            if PASSPORT_REGEX.fullmatch(passport_str):
                redacted_data['passport'] = self.redactor.redact_passport(passport_str)
                pii_found = True
        
        # UPI ID processing
        if 'upi_id' in original_data:
            upi_str = str(original_data['upi_id'])
            if UPI_REGEX.fullmatch(upi_str):
                redacted_data['upi_id'] = self.redactor.redact_upi(upi_str)
                pii_found = True
        
        return pii_found
    
    def _identify_combination_elements(self, original_data, redacted_data, markers):
        """Identify elements that form PII when combined"""
        
        # Full name analysis
        if 'name' in original_data:
            name_str = str(original_data['name'])
            if self.validator.is_valid_full_name(name_str):
                markers.add('name')
                redacted_data['name'] = self.redactor.redact_name(name_str)
        
        # Email address analysis
        if 'email' in original_data:
            email_str = str(original_data['email'])
            if EMAIL_REGEX.fullmatch(email_str):
                markers.add('email')
                redacted_data['email'] = self.redactor.redact_email(email_str)
        
        # Address analysis
        if 'address' in original_data:
            address_str = str(original_data['address'])
            if self.validator.is_valid_address(address_str):
                markers.add('address')
                redacted_data['address'] = self.redactor.redact_address(address_str)
        
        # IP address analysis
        if 'ip_address' in original_data:
            ip_str = str(original_data['ip_address'])
            if IP_REGEX.fullmatch(ip_str):
                markers.add('ip')
                redacted_data['ip_address'] = self.redactor.redact_ip_address(ip_str)
        
        # Device ID analysis
        if 'device_id' in original_data:
            device_str = str(original_data['device_id'])
            if len(device_str) > 6:
                markers.add('device')
                redacted_data['device_id'] = '[REDACTED_PII]'
        
        # First name + Last name combination
        if 'first_name' in original_data and 'last_name' in original_data:
            first_name = str(original_data['first_name']).strip()
            last_name = str(original_data['last_name']).strip()
            if first_name and last_name:
                markers.add('name')
                redacted_data['first_name'] = self.redactor.redact_name(first_name)
                redacted_data['last_name'] = self.redactor.redact_name(last_name)
        
        # City + PIN code combination
        if 'city' in original_data and 'pin_code' in original_data:
            pin_str = str(original_data['pin_code'])
            city_str = str(original_data['city']).strip()
            if re.match(r'\d{6}', pin_str) and city_str:
                markers.add('address')
                redacted_data['city'] = '[REDACTED_PII]'
                redacted_data['pin_code'] = '[REDACTED_PII]'
    
    def _restore_non_pii_data(self, original_data, redacted_data, markers):
        """Restore original data for non-PII single combination elements"""
        for marker_type in markers:
            if marker_type == 'name':
                for field in ['name', 'first_name', 'last_name']:
                    if field in original_data:
                        redacted_data[field] = original_data[field]
            elif marker_type == 'email' and 'email' in original_data:
                redacted_data['email'] = original_data['email']
            elif marker_type == 'address':
                for field in ['address', 'city', 'pin_code']:
                    if field in original_data:
                        redacted_data[field] = original_data[field]
            elif marker_type == 'ip' and 'ip_address' in original_data:
                redacted_data['ip_address'] = original_data['ip_address']
            elif marker_type == 'device' and 'device_id' in original_data:
                redacted_data['device_id'] = original_data['device_id']
    
    def _scan_text_fields(self, original_data, redacted_data):
        """Scan all text fields for embedded PII patterns"""
        pii_found = False
        
        for field_name, field_value in original_data.items():
            if not isinstance(field_value, str):
                continue
            
            # Skip fields already processed as direct PII
            skip_fields = {'name', 'email', 'address', 'phone', 'aadhar', 'passport', 'upi_id'}
            if field_name in skip_fields:
                continue
            
            modified_text = field_value
            
            # Search for embedded phone numbers
            for phone_match in PHONE_REGEX.finditer(field_value):
                phone_num = phone_match.group(1)
                if phone_num[0] in '6789':  # Valid Indian mobile prefixes
                    masked_phone = self.redactor.redact_phone(phone_num)
                    modified_text = modified_text.replace(phone_match.group(0), masked_phone)
                    pii_found = True
            
            # Search for embedded email addresses
            for email_match in EMAIL_REGEX.finditer(field_value):
                masked_email = self.redactor.redact_email(email_match.group(0))
                modified_text = modified_text.replace(email_match.group(0), masked_email)
                pii_found = True
            
            # Search for embedded Aadhaar numbers
            for aadhaar_match in AADHAAR_REGEX.finditer(field_value):
                aadhaar_num = aadhaar_match.group(1).replace(' ', '')
                if len(aadhaar_num) == 12 and not aadhaar_num.startswith('0'):
                    masked_aadhaar = self.redactor.redact_aadhaar(aadhaar_match.group(1))
                    modified_text = modified_text.replace(aadhaar_match.group(0), masked_aadhaar)
                    pii_found = True
            
            if modified_text != field_value:
                redacted_data[field_name] = modified_text
        
        return pii_found


def process_csv_data():
    """Main function to process CSV file and generate redacted output"""
    if len(sys.argv) != 2:
        print('Usage: python3 detector_saurav_pandey.py <input_csv_file>')
        sys.exit(1)
    
    input_filename = sys.argv[1]
    output_filename = 'redacted_output_saurav_pandey_name.csv'
    
    # Initialize the PII detection engine
    detector = PIIDetectionEngine()
    
    try:
        with open(input_filename, newline='', encoding='utf-8') as input_file, \
             open(output_filename, 'w', newline='', encoding='utf-8') as output_file:
            
            reader = csv.DictReader(input_file)
            output_columns = ['record_id', 'redacted_data_json', 'is_pii']
            writer = csv.DictWriter(output_file, fieldnames=output_columns)
            writer.writeheader()
            
            for row in reader:
                record_id = row['record_id']
                
                # Extract JSON data (handle different column names)
                json_content = row.get('Data_json') or row.get('data_json')
                
                if not json_content:
                    # Skip records without JSON data
                    continue
                
                # Clean and parse JSON data
                if json_content.startswith('"') and json_content.endswith('"'):
                    json_content = json_content[1:-1]
                json_content = json_content.replace('""', '"')
                
                try:
                    # Parse JSON with error recovery
                    try:
                        parsed_record = json.loads(json_content)
                    except json.JSONDecodeError:
                        # Attempt to fix common JSON formatting issues
                        fixed_json = re.sub(r'(:\s*)(\d{4}[-/.]\d{2}[-/.]\d{2})([\s,}])', r'\1"\2"\3', json_content)
                        fixed_json = re.sub(r'(:\s*)([a-zA-Z_][a-zA-Z0-9_]*)([\s,}])', r'\1"\2"\3', fixed_json)
                        parsed_record = json.loads(fixed_json)
                except Exception as error:
                    # Skip malformed records silently
                    continue
                
                # Analyze record for PII
                redacted_record, contains_pii = detector.analyze_record(parsed_record)
                
                # Write result to output file
                writer.writerow({
                    'record_id': record_id,
                    'redacted_data_json': json.dumps(redacted_record, ensure_ascii=False),
                    'is_pii': str(contains_pii)
                })
        
        print(f'Processing completed successfully. Output saved to {output_filename}')
        
    except FileNotFoundError:
        print(f'Error: Input file "{input_filename}" not found.')
        sys.exit(1)
    except Exception as error:
        print(f'An unexpected error occurred: {error}')
        sys.exit(1)


if __name__ == '__main__':
    process_csv_data()
