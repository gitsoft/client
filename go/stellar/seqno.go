package stellar

import (
	"sync"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/stellar1"
	"github.com/stellar/go/xdr"
)

// SeqnoProvider implements build.SequenceProvider.  It can be
// used for several transactions in a row.
type SeqnoProvider struct {
	mctx        libkb.MetaContext
	walletState *WalletState
	refresh     sync.Once
}

// NewSeqnoProvider creates a SeqnoProvider.  It also returns an `unlock` function
// that must be called after the operation(s) that used this seqno provider have
// been submitted.
//
// The idea here is to fix a race where multiple calls to send payments will
// make a SeqnoProvider and while they will consume seqnos in order, they are
// not guaranteed to be submitted in order.  In particular, the `dust storm`
// function in the bot has a tendency to expose the race.
func NewSeqnoProvider(mctx libkb.MetaContext, walletState *WalletState) (seqnoProvider *SeqnoProvider, unlock func()) {
	walletState.SeqnoLock()
	return &SeqnoProvider{
		mctx:        mctx,
		walletState: walletState,
	}, walletState.SeqnoUnlock
}

// SequenceForAccount implements build.SequenceProvider.
func (s *SeqnoProvider) SequenceForAccount(aid string) (xdr.SequenceNumber, error) {
	s.refresh.Do(func() {
		s.walletState.ForceSeqnoRefresh(s.mctx, stellar1.AccountID(aid))
	})
	seqno, err := s.walletState.AccountSeqnoAndBump(s.mctx.Ctx(), stellar1.AccountID(aid))
	if err != nil {
		return 0, err
	}

	s.mctx.Debug("SeqnoProvider.SequenceForAccount(%s) -> %d", aid, seqno)

	return xdr.SequenceNumber(seqno), nil
}
