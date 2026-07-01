package script_test

import (
	"crypto/rand"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// TestCSVLocktimeRoundtrip verifies that Script() and Decode() are inverses of
// each other for all block locktimes 1-200. Values in 81-96 previously decoded
// as value-80 due to a collision between OP_N opcode bytes and script number
// encoding (e.g. locktime=85 decoded back as 5).
func TestCSVLocktimeRoundtrip(t *testing.T) {
	pkBytes, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pk := pkBytes.PubKey()

	for v := uint32(1); v <= 200; v++ {
		lt := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: v}

		c := &script.CSVMultisigClosure{
			Locktime:        lt,
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{pk}},
		}

		s, err := c.Script()
		require.NoError(t, err, "Script() v=%d", v)

		decoded, err := script.DecodeClosure(s)
		require.NoError(t, err, "DecodeClosure v=%d", v)

		got, ok := decoded.(*script.CSVMultisigClosure)
		require.True(t, ok, "expected CSVMultisigClosure for v=%d, got %T", v, decoded)
		require.Equal(t, v, got.Locktime.Value, "locktime value mismatch for v=%d: got %d", v, got.Locktime.Value)
		require.Equal(t, arklib.LocktimeTypeBlock, got.Locktime.Type, "locktime type mismatch for v=%d", v)
	}
}

// TestConditionCSVLocktimeRoundtrip mirrors the VHTLC unilateral-claim leaf that
// broke .NET SDK e2e tests: a ConditionCSVMultisigClosure with a HASH160
// hashlock condition and the specific block delays 85/90/95 used in arkade-regtest.
// Those values fall in the 81-96 range where the old decode heuristic mangled
// the locktime (85→5), causing bytes.Equal to fail and arkd to reject the taptree.
func TestConditionCSVLocktimeRoundtrip(t *testing.T) {
	pkBytes, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pk := pkBytes.PubKey()

	// OP_HASH160 <20-byte hash> OP_EQUAL — same as VHTLC HashLockTapScript
	hash := make([]byte, 20)
	_, err = rand.Read(hash)
	require.NoError(t, err)
	condition, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(hash).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)

	for _, v := range []uint32{85, 90, 95} {
		lt := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: v}

		c := &script.ConditionCSVMultisigClosure{
			CSVMultisigClosure: script.CSVMultisigClosure{
				Locktime:        lt,
				MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{pk}},
			},
			Condition: condition,
		}

		s, err := c.Script()
		require.NoError(t, err, "Script() v=%d", v)

		decoded, err := script.DecodeClosure(s)
		require.NoError(t, err, "DecodeClosure v=%d", v)

		got, ok := decoded.(*script.ConditionCSVMultisigClosure)
		require.True(t, ok, "expected ConditionCSVMultisigClosure for v=%d, got %T", v, decoded)
		require.Equal(t, v, got.Locktime.Value, "locktime value mismatch for v=%d: got %d", v, got.Locktime.Value)
		require.Equal(t, arklib.LocktimeTypeBlock, got.Locktime.Type, "locktime type mismatch for v=%d", v)
	}
}
