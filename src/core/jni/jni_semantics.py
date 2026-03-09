"""JNI API semantics for taint transfer modeling."""
from __future__ import annotations

from typing import Dict


JNI_API_RULES: Dict[str, Dict[str, str]] = {
    # Java -> Native (data extraction)
    "GetStringUTFChars": {"direction": "java_to_native", "effect": "string_to_native"},
    "GetStringChars": {"direction": "java_to_native", "effect": "string_to_native"},
    "GetByteArrayElements": {"direction": "java_to_native", "effect": "array_to_native"},
    "GetIntArrayElements": {"direction": "java_to_native", "effect": "array_to_native"},
    "GetObjectArrayElement": {"direction": "java_to_native", "effect": "object_to_native"},
    # Native -> Java (callbacks / field writes)
    "CallObjectMethod": {"direction": "native_to_java", "effect": "callback"},
    "CallStaticObjectMethod": {"direction": "native_to_java", "effect": "callback"},
    "CallVoidMethod": {"direction": "native_to_java", "effect": "callback"},
    "CallStaticVoidMethod": {"direction": "native_to_java", "effect": "callback"},
    "SetObjectField": {"direction": "native_to_java", "effect": "field_write"},
    "SetIntField": {"direction": "native_to_java", "effect": "field_write"},
    "SetLongField": {"direction": "native_to_java", "effect": "field_write"},
}
