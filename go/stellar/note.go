package stellar

import (
	"context"
	"fmt"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/stellar1"
	"golang.org/x/crypto/nacl/secretbox"
)

// noteEncrypt encrypts a note for the logged-in user as well as optionally for `other`.
// For a self-note where `other` is nil, uses a secretbox box with a key derived from the logged-in user's PUK.
func noteEncrypt(ctx context.Context, g *libkb.GlobalContext, note stellar1.NoteContents, other *libkb.User) (res stellar1.EncryptedNote, err error) {
	if other != nil {
		return res, fmt.Errorf("TODO: shared note")
	}
	upkv2, _, err := g.GetUPAKLoader().LoadV2(libkb.NewLoadUserArgWithContext(ctx, g))
	if err != nil {
		return res, err
	}
	if upkv2 == nil {
		return res, fmt.Errorf("could not load logged-in user")
	}
	pukring, err := g.GetPerUserKeyring()
	if err != nil {
		return res, err
	}
	err = pukring.Sync(ctx)
	if err != nil {
		return res, err
	}
	pukGen := pukring.CurrentGeneration()
	pukSeed, err := pukring.GetSeedByGeneration(ctx, pukGen)
	if err != nil {
		return res, err
	}
	symmetricKey, err := pukSeed.DeriveSymmetricKey(libkb.DeriveReasonPUKStellarSelfNote)
	if err != nil {
		return res, err
	}
	res, err = noteEncryptHelper(ctx, note, symmetricKey)
	if err != nil {
		return res, err
	}
	res.Sender = stellar1.NoteRecipient{
		User:   upkv2.Current.ToUserVersion(),
		PukGen: pukGen,
	}
	return res, fmt.Errorf("note todo")
}

// noteEncryptHelper does the encryption part and returns a partially populated result.
func noteEncryptHelper(ctx context.Context, note stellar1.NoteContents, symmetricKey libkb.NaclSecretBoxKey) (res stellar1.EncryptedNote, err error) {
	// Msgpack
	clearpack, err := libkb.MsgpackEncode(note)
	if err != nil {
		return res, err
	}

	// Secretbox
	var nonce [libkb.NaclDHNonceSize]byte
	nonce, err = libkb.RandomNaclDHNonce()
	if err != nil {
		return res, err
	}
	secbox := secretbox.Seal(nil, clearpack[:], &nonce, (*[libkb.NaclSecretBoxKeySize]byte)(&symmetricKey))

	return stellar1.EncryptedNote{
		V: 1,
		E: secbox,
		N: nonce,
	}, nil
}
