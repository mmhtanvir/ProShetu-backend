from rest_framework import serializers

from .models import IdentityDocument

# Fields we accept per document type. `number_field` is the lookup key.
DOC_SCHEMA = {
    "birth_certificate": {
        "number_field": "birth_registration_number",
        "fields": ["full_name", "date_of_birth", "birth_registration_number",
                   "father_name", "mother_name", "place_of_birth"],
        "required_match": ["full_name", "date_of_birth"],
    },
    "nid": {
        "number_field": "nid_number",
        "fields": ["full_name", "date_of_birth", "nid_number",
                   "father_name", "mother_name"],
        "required_match": ["full_name", "date_of_birth"],
    },
}


class DocumentIngestSerializer(serializers.Serializer):
    doc_type = serializers.ChoiceField(choices=list(DOC_SCHEMA.keys()))
    fields = serializers.DictField(child=serializers.CharField(allow_blank=False))

    def validate(self, attrs):
        schema = DOC_SCHEMA[attrs["doc_type"]]
        num_field = schema["number_field"]
        provided = attrs["fields"]
        if num_field not in provided:
            raise serializers.ValidationError(
                f"'{num_field}' is required for {attrs['doc_type']}"
            )
        # Drop any keys not in the schema (don't store arbitrary fields).
        attrs["fields"] = {k: v for k, v in provided.items()
                           if k in schema["fields"]}
        return attrs


class VerifyRequestSerializer(serializers.Serializer):
    doc_type = serializers.ChoiceField(choices=list(DOC_SCHEMA.keys()))
    # The user-entered data to check against the stored document.
    fields = serializers.DictField(child=serializers.CharField(allow_blank=False))

    def validate(self, attrs):
        schema = DOC_SCHEMA[attrs["doc_type"]]
        num_field = schema["number_field"]
        if num_field not in attrs["fields"]:
            raise serializers.ValidationError(
                f"'{num_field}' is required to locate the document"
            )
        for req in schema["required_match"]:
            if req not in attrs["fields"]:
                raise serializers.ValidationError(
                    f"'{req}' is required for verification"
                )
        attrs["fields"] = {k: v for k, v in attrs["fields"].items()
                           if k in schema["fields"]}
        return attrs
