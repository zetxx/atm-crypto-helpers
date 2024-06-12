# atm-crypto-helpers
Crypto helper functions for Atm/Pos devices

## Master (Card) key derivation

### Parameters

- _emvVersion_ - one of _4.0_, _4.1_, _4.2_, _4.3_
    - _4.0_ - same as _option A_ of the other versions
    - _4.1_, _4.2_, _4.3_ - two options for each one, depending on the _type_ parameter:
        - _option A_ - same as _4.0_
        - _option B_ - available for _emvVersion_ _4.1_, _4.2_ and _4.3_

    **NOTE: Thales Payshield command _KQ_ supports only emvVersion 4.0, therefore _option A_**

## Session key derivation

### Parameters

- _emvVersion_ - one of _4.0_, _4.1_, _4.2_, _4.3_
    - _4,0_, _4.1_ - same as Thales _EMV2000_
    - _4.2_ - same as Thales common session key derivation
    - _4.3_ - same as _4.2_ in case of double length key (16 bytes) and _algorithmBlockSize_ 8 bytes (DES key)

## Thales - EMV mapping

- Command code = KQ (EMV v.3), sceme ID = 0
    - 
- Command code = KQ (EMV v.3), sceme ID = 1

- Command code = KQ (EMV v.3), sceme ID = 2

- Command code = KW (EMV v.4), sceme ID = 0
    - _emvVersion_ - _4.1_
    - _type_ - _a_
    - _macAlgorithm_

- Command code = KW (EMV v.4), sceme ID = 1
    - _emvVersion_ - _4.1_
    - _type_ - _b_
    - _macAlgorithm_

- Command code = KW (EMV v.4), sceme ID = 2
    - _emvVersion_ - _4.2_ OR _4.3_
    - _type_ - _a_
    - _macAlgorithm_

- Command code = KW (EMV v.4), sceme ID = 3
    - _emvVersion_ - _v4.3_
    - _type_ - _b_
    - _algorithmBlockSize_ - _8_
    - _macAlgorithm_ = _3_

## TR31 key block decryption (keyblockDecrypt)

Supports only algorithm B as defined in Ref 8 section 5.3.2.1
 of TR31 keyblock specifications.
