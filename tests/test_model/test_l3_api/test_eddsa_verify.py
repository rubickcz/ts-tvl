from typing import Any, Dict
import hashlib

import pytest
from _pytest.fixtures import SubRequest

from tvl.api.l3_api import TsL3EddsaSignCommand, TsL3EddsaSignResult, TsL3EddsaVerifyCommand, TsL3EddsaVerifyResult
from tvl.constants import L3ResultFieldEnum
from tvl.host.host import Host
from tvl.targets.model.internal.ecc_keys import Origins, EdDSAKeyMemLayout

from ..utils import UtilsEcc, as_slow


@pytest.fixture(scope="function")
def initialize_eddsa_keys(model_configuration: Dict[str, Any]):
    # Initialize EdDSA keys in the model configuration
    eddsa_keys = {}
    
    for slot in UtilsEcc.VALID_INDICES:
        # Use a deterministic key based on the slot number to ensure consistency
        key_seed = f"test_key_seed_{slot}".encode()
        key = hashlib.sha256(key_seed).digest()
        key_layout = EdDSAKeyMemLayout.from_key(key, Origins.ECC_KEY_GENERATE)
        
        eddsa_keys[slot] = {
            "s": key_layout.s,
            "prefix": key_layout.prefix,
            "a": key_layout.a,
            "origin": key_layout.origin
        }
    
    # Update the model configuration with the EdDSA keys
    model_configuration.update({"r_ecc_keys": eddsa_keys})


@pytest.fixture()
def slot(initialize_eddsa_keys, request: SubRequest):
    # Simply yield the slot index, keys are already initialized
    yield request.param


@pytest.mark.parametrize("slot", as_slow(UtilsEcc.VALID_INDICES, 10), indirect=True)
def test_eddsa_verify_valid_signature(slot: int, host: Host):
    """Test that EDDSA_Verify correctly validates a signature created by EDDSA_Sign."""
    # First, sign a message using EDDSA_Sign
    message = b"Hello, World! This is a test message for EdDSA verification."
    
    sign_command = TsL3EddsaSignCommand(slot=slot, msg=message)
    sign_result = host.send_command(sign_command)
    
    assert isinstance(sign_result, TsL3EddsaSignResult)
    assert sign_result.result.value == L3ResultFieldEnum.OK
    
    # Now verify the signature using EDDSA_Verify
    verify_command = TsL3EddsaVerifyCommand(
        slot=slot,
        msg=message,
        r=sign_result.r.value,
        s=sign_result.s.value
    )
    verify_result = host.send_command(verify_command)
    
    assert isinstance(verify_result, TsL3EddsaVerifyResult)
    assert verify_result.result.value == TsL3EddsaVerifyResult.ResultEnum.OK


@pytest.mark.parametrize("slot", as_slow(UtilsEcc.VALID_INDICES, 10), indirect=True)
def test_eddsa_verify_invalid_signature(slot: int, host: Host):
    """Test that EDDSA_Verify correctly rejects an invalid signature."""
    message = b"Hello, World! This is a test message for EdDSA verification."
    
    # Create an invalid signature (all zeros)
    invalid_r = b'\x00' * 32
    invalid_s = b'\x00' * 32
    
    verify_command = TsL3EddsaVerifyCommand(
        slot=slot,
        msg=message,
        r=invalid_r,
        s=invalid_s
    )
    verify_result = host.send_command(verify_command)
    
    assert isinstance(verify_result, TsL3EddsaVerifyResult)
    assert verify_result.result.value == TsL3EddsaVerifyResult.ResultEnum.FAIL


@pytest.mark.parametrize("slot", as_slow(UtilsEcc.VALID_INDICES, 10), indirect=True)
def test_eddsa_verify_wrong_message(slot: int, host: Host):
    """Test that EDDSA_Verify correctly rejects a signature for a different message."""
    # First, sign a message using EDDSA_Sign
    original_message = b"Original message"
    different_message = b"Different message"
    
    sign_command = TsL3EddsaSignCommand(slot=slot, msg=original_message)
    sign_result = host.send_command(sign_command)
    
    assert isinstance(sign_result, TsL3EddsaSignResult)
    assert sign_result.result.value == L3ResultFieldEnum.OK
    
    # Try to verify the signature with a different message
    verify_command = TsL3EddsaVerifyCommand(
        slot=slot,
        msg=different_message,
        r=sign_result.r.value,
        s=sign_result.s.value
    )
    verify_result = host.send_command(verify_command)
    
    assert isinstance(verify_result, TsL3EddsaVerifyResult)
    assert verify_result.result.value == TsL3EddsaVerifyResult.ResultEnum.FAIL


@pytest.mark.parametrize("slot", as_slow(UtilsEcc.VALID_INDICES, 10))
def test_eddsa_verify_no_key(host: Host, slot: int):
    """Test that EDDSA_Verify returns INVALID_KEY when no key exists in the slot."""
    # This test doesn't use the initialize_eddsa_keys fixture, so no keys are in the slots
    
    verify_command = TsL3EddsaVerifyCommand(
        slot=slot,
        msg=b"test message",
        r=b'\x00' * 32,
        s=b'\x00' * 32
    )
    verify_result = host.send_command(verify_command)
    
    assert isinstance(verify_result, TsL3EddsaVerifyResult)
    assert verify_result.result.value == TsL3EddsaVerifyResult.ResultEnum.INVALID_KEY


@pytest.mark.parametrize("slot", as_slow(UtilsEcc.INVALID_INDICES, 10))
def test_eddsa_verify_invalid_slot(host: Host, slot: int):
    """Test that EDDSA_Verify returns UNAUTHORIZED for invalid slot indices."""
    
    verify_command = TsL3EddsaVerifyCommand(
        slot=slot,
        msg=b"test message",
        r=b'\x00' * 32,
        s=b'\x00' * 32
    )
    verify_result = host.send_command(verify_command)
    
    assert isinstance(verify_result, TsL3EddsaVerifyResult)
    assert verify_result.result.value == L3ResultFieldEnum.UNAUTHORIZED 