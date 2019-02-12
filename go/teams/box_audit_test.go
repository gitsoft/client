package teams

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keybase/client/go/kbtest"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/stretchr/testify/require"
)

// TODO test for calculate ClientSummary and etc
func toErr(attempt keybase1.BoxAuditAttempt) error {
	if attempt.Error != nil {
		return errors.New(*attempt.Error)
	}
	return nil
}

func _() {
	spew.Dump("")
}

// USE RACE CHECKER
// also test for consistency between LRU and log

func mustGetBoxState(tc *libkb.TestContext, mctx libkb.MetaContext, teamID keybase1.TeamID) (*BoxAuditLog, *BoxAuditQueue, *BoxAuditJail) {
	log := mustGetBoxLog(*tc, mctx, teamID)
	queue := mustGetQueue(*tc, mctx, teamID)
	jail := mustGetJail(*tc, mctx, teamID)
	return log, queue, jail
}

func mustGetBoxLog(tc libkb.TestContext, mctx libkb.MetaContext, teamID keybase1.TeamID) *BoxAuditLog {
	var log BoxAuditLog
	found, err := maybeGetVersionedFromDisk(mctx, BoxAuditLogDbKey(teamID), &log, CurrentBoxAuditVersion)
	require.NoError(tc.T, err)
	if !found {
		return nil
	}
	return &log
}

func mustGetQueue(tc libkb.TestContext, mctx libkb.MetaContext, teamID keybase1.TeamID) *BoxAuditQueue {
	var queue BoxAuditQueue
	found, err := maybeGetVersionedFromDisk(mctx, BoxAuditQueueDbKey(), &queue, CurrentBoxAuditVersion)
	require.NoError(tc.T, err)
	if !found {
		return nil
	}
	return &queue
}

func mustGetJail(tc libkb.TestContext, mctx libkb.MetaContext, teamID keybase1.TeamID) *BoxAuditJail {
	var jail BoxAuditJail
	found, err := maybeGetVersionedFromDisk(mctx, BoxAuditJailDbKey(), &jail, CurrentBoxAuditVersion)
	require.NoError(tc.T, err)
	if !found {
		return nil
	}
	return &jail
}

func TestBoxAuditAttempt(t *testing.T) {
	fus, tcs, cleanup := setupNTests(t, 3)
	defer cleanup()

	_, bU, cU := fus[0], fus[1], fus[2]
	aTc, bTc, cTc := tcs[0], tcs[1], tcs[2]
	aM, bM, cM := libkb.NewMetaContextForTest(*aTc), libkb.NewMetaContextForTest(*bTc), libkb.NewMetaContextForTest(*cTc)
	aA, bA, cA := aTc.G.GetTeamBoxAuditor(), bTc.G.GetTeamBoxAuditor(), cTc.G.GetTeamBoxAuditor()

	t.Logf("A creates team")
	teamName, teamID := createTeam2(*aTc)

	t.Logf("adding B as admin")
	_, err := AddMember(aM.Ctx(), aTc.G, teamName.String(), bU.Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)

	t.Logf("adding C as reader")
	_, err = AddMember(aM.Ctx(), aTc.G, teamName.String(), cU.Username, keybase1.TeamRole_READER)
	require.NoError(t, err)

	require.NoError(t, toErr(aA.Attempt(aM, teamID, false)), "A can attempt")
	require.NoError(t, toErr(bA.Attempt(aM, teamID, false)), "B can attempt")

	attempt := aA.Attempt(aM, teamID, false)
	require.NoError(t, toErr(attempt))
	require.Equal(t, attempt.Result, keybase1.BoxAuditAttemptResult_OK_VERIFIED, "owner can attempt")
	require.Equal(t, *attempt.Generation, keybase1.PerTeamKeyGeneration(1))

	attempt = bA.Attempt(bM, teamID, false)
	require.NoError(t, toErr(attempt))
	require.Equal(t, attempt.Result, keybase1.BoxAuditAttemptResult_OK_VERIFIED, "admins can attempt")
	require.Equal(t, *attempt.Generation, keybase1.PerTeamKeyGeneration(1))

	attempt = cA.Attempt(cM, teamID, false)
	require.NoError(t, toErr(attempt))
	require.Equal(t, attempt.Result, keybase1.BoxAuditAttemptResult_OK_NOT_ATTEMPTED, "readers can attempt but don't verify")
	require.Equal(t, *attempt.Generation, keybase1.PerTeamKeyGeneration(1))

	kbtest.RotatePaper(*cTc, cU)
	attempt = aA.Attempt(aM, teamID, false)
	require.Error(t, toErr(attempt), "team not rotated after puk rotate so attempt fails")
	team, err := Load(context.TODO(), aTc.G, keybase1.LoadTeamArg{Name: teamName.String(), ForceRepoll: true})
	require.NoError(t, err)
	err = team.Rotate(aM.Ctx())
	require.NoError(t, err)
	attempt = aA.Attempt(aM, teamID, false)
	require.NoError(t, toErr(attempt), "team rotated, so audit works")

	t.Logf("check after rotate puk")
	kbtest.RotatePaper(*cTc, cU)
	attempt = aA.Attempt(aM, teamID, false)
	require.Error(t, toErr(attempt), "team not rotated after puk rotate so attempt fails")
	attempt = aA.Attempt(aM, teamID, true)
	require.NoError(t, toErr(attempt), "rotate-before-attempt option works")

	t.Logf("check after reset")
	kbtest.ResetAccount(*cTc, cU)
	attempt = aA.Attempt(aM, teamID, false)
	require.Error(t, toErr(attempt), "team not rotated after reset")
	attempt = aA.Attempt(aM, teamID, true)
	require.NoError(t, toErr(attempt), "attempt OK after rotate")

	attempt = cA.Attempt(cM, teamID, false)
	require.Error(t, toErr(attempt), "check that someone not in a team cannot audit")

	t.Logf("C provisions and A adds C back after account reset")
	err = cU.Login(cTc.G)
	require.NoError(t, err)
	_, err = AddMember(aM.Ctx(), aTc.G, teamName.String(), cU.Username, keybase1.TeamRole_READER)
	require.NoError(t, err)

	t.Logf("check after delete")
	kbtest.DeleteAccount(*cTc, cU)
	attempt = aA.Attempt(aM, teamID, false)
	require.Error(t, toErr(attempt), "team not rotated after delete")
	attempt = aA.Attempt(aM, teamID, true)
	require.NoError(t, toErr(attempt), "attempt OK after rotate")
}

func TestBoxAuditAudit(t *testing.T) {
	fus, tcs, cleanup := setupNTests(t, 3)
	defer cleanup()

	_, bU, cU := fus[0], fus[1], fus[2]
	aTc, bTc, cTc := tcs[0], tcs[1], tcs[2]
	aM, bM, cM := libkb.NewMetaContextForTest(*aTc), libkb.NewMetaContextForTest(*bTc), libkb.NewMetaContextForTest(*cTc)
	aA, bA, cA := aTc.G.GetTeamBoxAuditor(), bTc.G.GetTeamBoxAuditor(), cTc.G.GetTeamBoxAuditor()

	t.Logf("A creates team")
	teamName, teamID := createTeam2(*aTc)

	t.Logf("adding B as admin")
	_, err := AddMember(aM.Ctx(), aTc.G, teamName.String(), bU.Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)

	t.Logf("adding C as reader")
	_, err = AddMember(aM.Ctx(), aTc.G, teamName.String(), cU.Username, keybase1.TeamRole_READER)
	require.NoError(t, err)

	require.NoError(t, aA.BoxAuditTeam(aM, teamID), "A can audit")
	require.NoError(t, bA.BoxAuditTeam(bM, teamID), "B can audit")
	require.NoError(t, cA.BoxAuditTeam(cM, teamID), "C can audit (this is vacuous, since C is a reader)")

	var nullstring *string
	g1 := keybase1.PerTeamKeyGeneration(1)

	t.Logf("check A's view of the successful audit in db")
	log, queue, jail := mustGetBoxState(aTc, aM, teamID)
	log.Audits[0].ID = nil
	log.Audits[0].Attempts[0].Ctime = 0
	require.Equal(t, *log, BoxAuditLog{
		Audits: []BoxAudit{
			BoxAudit{
				ID: nil,
				Attempts: []keybase1.BoxAuditAttempt{
					keybase1.BoxAuditAttempt{
						Ctime:      0,
						Error:      nullstring,
						Result:     keybase1.BoxAuditAttemptResult_OK_VERIFIED,
						Generation: &g1,
					},
				},
			},
		},
		InProgress: false,
		Version:    CurrentBoxAuditVersion,
	})
	require.Nil(t, queue)
	require.Equal(t, *jail, BoxAuditJail{
		TeamIDs: map[keybase1.TeamID]bool{},
		Version: CurrentBoxAuditVersion,
	})

	t.Logf("check B's view of the successful audit in db")
	log, queue, jail = mustGetBoxState(bTc, bM, teamID)
	log.Audits[0].ID = nil
	log.Audits[0].Attempts[0].Ctime = 0
	require.Equal(t, *log, BoxAuditLog{
		Audits: []BoxAudit{
			BoxAudit{
				ID: nil,
				Attempts: []keybase1.BoxAuditAttempt{
					keybase1.BoxAuditAttempt{
						Ctime:      0,
						Error:      nullstring,
						Result:     keybase1.BoxAuditAttemptResult_OK_VERIFIED,
						Generation: &g1,
					},
				},
			},
		},
		InProgress: false,
		Version:    CurrentBoxAuditVersion,
	})
	require.Nil(t, queue)
	require.Equal(t, *jail, BoxAuditJail{
		TeamIDs: map[keybase1.TeamID]bool{},
		Version: CurrentBoxAuditVersion,
	})

	t.Logf("check C's view of the successful no-op audit in db")
	log, queue, jail = mustGetBoxState(cTc, cM, teamID)
	log.Audits[0].ID = nil
	log.Audits[0].Attempts[0].Ctime = 0
	require.Equal(t, *log, BoxAuditLog{
		Audits: []BoxAudit{
			BoxAudit{
				ID: nil,
				Attempts: []keybase1.BoxAuditAttempt{
					keybase1.BoxAuditAttempt{
						Ctime:      0,
						Error:      nullstring,
						Result:     keybase1.BoxAuditAttemptResult_OK_NOT_ATTEMPTED,
						Generation: &g1,
					},
				},
			},
		},
		InProgress: false,
		Version:    CurrentBoxAuditVersion,
	})
	require.Nil(t, queue)
	require.Equal(t, *jail, BoxAuditJail{
		TeamIDs: map[keybase1.TeamID]bool{},
		Version: CurrentBoxAuditVersion,
	})

	t.Logf("checking state after failed attempts")
	t.Logf("disable autorotate on retry")
	aTc.G.TestOptions.NoAutorotateOnBoxAuditRetry = true
	t.Logf("c rotates and a check's state")
	kbtest.RotatePaper(*cTc, cU)
	err = aA.BoxAuditTeam(aM, teamID)
	require.Error(t, err, "audit failure on unrotated puk")
	_, ok := err.(NonfatalBoxAuditError)
	require.True(t, ok)
	log, queue, jail = mustGetBoxState(aTc, aM, teamID)
	require.Equal(t, len(log.Audits), 2)
	require.True(t, log.InProgress, "failed audit causes it to be in progress")
	require.Equal(t, len(queue.Items), 1)
	require.Equal(t, queue.Items[0].TeamID, teamID)
	require.Equal(t, queue.Version, CurrentBoxAuditVersion)
	err = aA.BoxAuditTeam(aM, teamID)
	require.Error(t, err, "another audit failure on unrotated puk")
	log, queue, jail = mustGetBoxState(aTc, aM, teamID)
	require.Equal(t, len(queue.Items), 1, "no duplicates in retry queue")

	t.Logf("checking that we can load a team in retry queue, but that is not jailed yet")
	_, err = Load(context.TODO(), aTc.G, keybase1.LoadTeamArg{Name: teamName.String(), ForceRepoll: true})
	require.NoError(t, err)

	t.Logf("rotate until we hit max retry attempts; should result in fatal error")
	for i := 0; i < MaxBoxAuditRetryAttempts; i++ {
		err = aA.BoxAuditTeam(aM, teamID)
		spew.Dump(err)
		require.Error(t, err, "another audit failure on unrotated puk")
	}
	_, ok = err.(FatalBoxAuditError)
	spew.Dump(err)
	require.True(t, ok)
	log, queue, jail = mustGetBoxState(aTc, aM, teamID)
	require.Equal(t, len(log.Last().Attempts), MaxBoxAuditRetryAttempts+2)
	require.True(t, log.InProgress, "fatal state still counts as in progress even though it won't be retried")
	require.Equal(t, len(queue.Items), 0, "jailed teams not in retry queue")
	require.Equal(t, *jail, BoxAuditJail{
		TeamIDs: map[keybase1.TeamID]bool{
			teamID: true,
		},
		Version: CurrentBoxAuditVersion,
	})

	// NOTE We may eventually cause the jailed team load that did not pass
	// reaudit to fail entirely instead of just putting up a black bar in the
	// GUI.
	t.Logf("checking that we can load a jailed team that won't pass auto-reaudit")
	_, err = Load(context.TODO(), aTc.G, keybase1.LoadTeamArg{Name: teamName.String(), ForceRepoll: true})
	require.NoError(t, err)

	t.Logf("reenable autorotate on retry")
	aTc.G.TestOptions.NoAutorotateOnBoxAuditRetry = false
	err = aA.BoxAuditTeam(aM, teamID)
	require.NoError(t, err, "no error since we rotate on retry now")
	log, queue, jail = mustGetBoxState(aTc, aM, teamID)
	require.False(t, log.InProgress)
	attempts := log.Last().Attempts
	require.Equal(t, attempts[len(attempts)-1].Result, keybase1.BoxAuditAttemptResult_OK_VERIFIED)
	require.Equal(t, len(queue.Items), 0, "not in queue")
	require.Equal(t, len(jail.TeamIDs), 0, "unjailed")
}

// TestBoxAuditRaces makes 3 users, 3 teams with all 3 users, and audits all
// of them many times at the same time in separate goroutines.  If tested with
// the -race option, it will fail if there's any data races. Also, we check
// that all the routines eventually finish, which might catch some deadlocks.
// Note that the race detector only catches memory races, so it doesn't really
// mean there are no data races in the code even if it passes the detector, i.e.,
// one goroutine could have overwritten a queue add of another goroutine, and this
// would not be caught by the detector.
func TestBoxAuditRaces(t *testing.T) {
	fus, tcs, cleanup := setupNTests(t, 3)
	defer cleanup()

	aU, bU, cU := fus[0], fus[1], fus[2]
	aTc, bTc, cTc := tcs[0], tcs[1], tcs[2]
	aM, bM, cM := libkb.NewMetaContextForTest(*aTc), libkb.NewMetaContextForTest(*bTc), libkb.NewMetaContextForTest(*cTc)
	aA, bA, cA := aTc.G.GetTeamBoxAuditor(), bTc.G.GetTeamBoxAuditor(), cTc.G.GetTeamBoxAuditor()

	aTeamName, aTeamID := createTeam2(*aTc)
	_, err := AddMember(aM.Ctx(), aTc.G, aTeamName.String(), bU.Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)
	_, err = AddMember(aM.Ctx(), aTc.G, aTeamName.String(), cU.Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)

	bTeamName, bTeamID := createTeam2(*bTc)
	_, err = AddMember(bM.Ctx(), bTc.G, bTeamName.String(), aU.Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)
	_, err = AddMember(bM.Ctx(), bTc.G, bTeamName.String(), cU.Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)

	cTeamName, cTeamID := createTeam2(*cTc)
	_, err = AddMember(cM.Ctx(), cTc.G, cTeamName.String(), aU.Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)
	_, err = AddMember(cM.Ctx(), cTc.G, cTeamName.String(), bU.Username, keybase1.TeamRole_ADMIN)
	require.NoError(t, err)

	// We do this so the audits will access the shared jail and queue data
	// structures, not just the logs.
	t.Logf("Turning off autorotate on retry and putting teams in failing audit state")
	aTc.G.TestOptions.NoAutorotateOnBoxAuditRetry = true
	kbtest.RotatePaper(*aTc, aU)
	kbtest.RotatePaper(*bTc, bU)
	kbtest.RotatePaper(*cTc, cU)

	auditors := []libkb.TeamBoxAuditor{aA, bA, cA}
	metacontexts := []libkb.MetaContext{aM, bM, cM}
	teamIDs := []keybase1.TeamID{aTeamID, bTeamID, cTeamID}
	var wg sync.WaitGroup
	total := 9
	errCh := make(chan error, total)
	wg.Add(total)
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			go func(i, j int) {
				auditErr := auditors[i].BoxAuditTeam(metacontexts[i], teamIDs[j])
				errCh <- auditErr
				wg.Done()
			}(i, j)
		}
	}
	wg.Wait()
	i := 0
	for err := range errCh {
		require.NotNil(t, err)
		boxErr := err.(NonfatalBoxAuditError)
		require.True(t, strings.Contains(boxErr.inner.Error(), "box summary hash mismatch"))
		// stop reading after 9 handled errors, otherwise the for loop goes
		// forever since we don't close errCh
		i++
		if i >= total {
			break
		}
	}
}
