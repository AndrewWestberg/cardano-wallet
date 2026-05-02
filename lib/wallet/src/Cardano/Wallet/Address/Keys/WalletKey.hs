{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
-- ghc , at least 8.10.7 cannot figure out the constraint is necessary in
-- liftRawKey, so we disable the warning.
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- | Interface over keys / address types
module Cardano.Wallet.Address.Keys.WalletKey
    ( liftRawKey
    , getRawKey
    , keyTypeDescriptor
    , digest
    , publicKey
    , changePassphraseNew
    , rewrapToV2
    , hashVerificationKey
    , AfterByron
    , afterByron
    ) where

import Cardano.Address.Derivation
    ( XPrv
    , xpubPublicKey
    )
import Cardano.Crypto.Wallet
    ( XPrvError
    )
import Cardano.Address.KeyHash
    ( KeyHash (KeyHash)
    , KeyRole
    )
import Cardano.Crypto.Wallet
    ( XPub
    , rewrapXPrvToV2
    , toXPub
    , unXPub
    )
import Cardano.Wallet.Address.Derivation.Byron
    ( ByronKey (..)
    , byronKey
    , hdPassphrase
    )
import Cardano.Wallet.Address.Derivation.Icarus
    ( IcarusKey (..)
    , icarusKey
    )
import Cardano.Wallet.Address.Derivation.SharedKey
    ( SharedKey (..)
    , sharedKey
    )
import Cardano.Wallet.Address.Derivation.Shelley
    ( ShelleyKey (..)
    , shelleyKey
    )
import Cardano.Wallet.Flavor
    ( Excluding
    , KeyFlavorS (..)
    )
import Cardano.Wallet.Primitive.Passphrase
    ( PassphraseScheme
    , changePassphraseXPrv
    )
import Cardano.Wallet.Primitive.Passphrase.Types
    ( Passphrase (..)
    )
import Control.Lens
    ( over
    , view
    , (^.)
    )
import Cryptography.Hash.Blake
    ( blake2b224
    )
import Cryptography.Hash.Core
    ( Digest
    , HashAlgorithm
    , hash
    )
import Prelude

-- | Re-encrypt a private key using a different passphrase.
--
-- **Important**:
-- This function doesn't check that the old passphrase is correct! Caller is
-- expected to have already checked that. Using an incorrect passphrase here
-- will lead to very bad thing.
changePassphraseNew
    :: KeyFlavorS key
    -- ^ The type of key to serialize.
    -> (PassphraseScheme, Passphrase "user")
    -- ^ Old passphrase.
    -> (PassphraseScheme, Passphrase "user")
    -- ^ New passphrase.
    -> key depth XPrv
    -- ^ Old private key.
    -> Either XPrvError (key depth XPrv)
changePassphraseNew = \case
    ByronKeyS -> \old new key ->
        fmap
            (\masterKey -> ByronKey
                { getKey = masterKey
                , derivationPath = derivationPath key
                , payloadPassphrase = hdPassphrase (toXPub masterKey)
                }
            )
            (changePassphraseXPrv old new $ key ^. byronKey)
    IcarusKeyS -> \old new -> fmap IcarusKey . changePassphraseXPrv old new . view icarusKey
    ShelleyKeyS -> \old new -> fmap ShelleyKey . changePassphraseXPrv old new . view shelleyKey
    SharedKeyS -> \old new -> fmap SharedKey . changePassphraseXPrv old new . view sharedKey

rewrapToV2
    :: KeyFlavorS key
    -> Passphrase "encryption"
    -> key depth XPrv
    -> Either XPrvError (key depth XPrv)
rewrapToV2 = \case
    ByronKeyS -> \pwd key ->
        fmap
            (\masterKey -> ByronKey
                { getKey = masterKey
                , derivationPath = derivationPath key
                , payloadPassphrase = hdPassphrase (toXPub masterKey)
                }
            )
            (rewrapXPrvToV2 pwd $ key ^. byronKey)
    IcarusKeyS -> \pwd -> fmap IcarusKey . rewrapXPrvToV2 pwd . view icarusKey
    ShelleyKeyS -> \pwd -> fmap ShelleyKey . rewrapXPrvToV2 pwd . view shelleyKey
    SharedKeyS -> \pwd -> fmap SharedKey . rewrapXPrvToV2 pwd . view sharedKey

-- | Extract the public key part of a private key.
publicKey
    :: KeyFlavorS key
    -- ^ The type of key to serialize.
    -> key depth XPrv
    -- ^ Private key.
    -> key depth XPub
publicKey = \case
    ByronKeyS -> over byronKey toXPub
    IcarusKeyS -> over icarusKey toXPub
    ShelleyKeyS -> over shelleyKey toXPub
    SharedKeyS -> over sharedKey toXPub

-- | Hash a public key to some other representation.
digest
    :: HashAlgorithm a
    => KeyFlavorS key
    -- ^ The type of key to serialize.
    -> key depth XPub
    -- ^ Public key.
    -> Digest a
digest k = hash . unXPub . getRawKey k

-- | Get a short, human-readable string descriptor that uniquely identifies
--   the specified key type.
keyTypeDescriptor
    :: KeyFlavorS k
    -- ^ The type of key to serialize.
    -> String
keyTypeDescriptor = \case
    ByronKeyS -> "rnd"
    IcarusKeyS -> "ica"
    ShelleyKeyS -> "she"
    SharedKeyS -> "sha"

-- | Unwrap the 'WalletKey' to use the 'XPrv' or 'XPub'.
getRawKey
    :: KeyFlavorS key
    -- ^ The type of key to serialize.
    -> key depth raw
    -- ^ The key to unwrap, public or private.
    -> raw
getRawKey = \case
    ByronKeyS -> view byronKey
    IcarusKeyS -> view icarusKey
    ShelleyKeyS -> view shelleyKey
    SharedKeyS -> view sharedKey

type AfterByron k = Excluding '[ByronKey] k

-- | Lift 'XPrv' or 'XPub' to 'WalletKey'.
liftRawKey
    :: AfterByron key
    => KeyFlavorS key
    -- ^ The type of key to serialize.
    -> raw
    -- ^ The key to unwrap, public or private.
    -> key depth raw
liftRawKey = \case
    IcarusKeyS -> IcarusKey
    ShelleyKeyS -> ShelleyKey
    SharedKeyS -> SharedKey

afterByron
    :: KeyFlavorS k
    -> (AfterByron k => KeyFlavorS k -> x)
    -> Maybe x
afterByron x h = case x of
    ByronKeyS -> Nothing
    ShelleyKeyS -> Just $ h ShelleyKeyS
    IcarusKeyS -> Just $ h IcarusKeyS
    SharedKeyS -> Just $ h SharedKeyS

hashVerificationKey
    :: KeyFlavorS k
    -> KeyRole
    -> k depth XPub
    -> KeyHash
hashVerificationKey key keyRole =
    KeyHash keyRole . blake2b224 . xpubPublicKey . getRawKey key
