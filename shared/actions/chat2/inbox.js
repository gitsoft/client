// @flow
import * as Chat2Gen from '../chat2-gen'
import * as Constants from '../../constants/chat2'
import * as Flow from '../../util/flow'
import * as I from 'immutable'
import * as RPCChatTypes from '../../constants/types/rpc-chat-gen'
import * as RPCTypes from '../../constants/types/rpc-gen'
import * as Saga from '../../util/saga'
import * as Types from '../../constants/types/chat2'
import * as UsersGen from '../users-gen'
import * as WaitingGen from '../waiting-gen'
import logger from '../../logger'
import type {TypedState, TypedActions} from '../../util/container'

// Ask the service to refresh the inbox
const inboxRefresh = (
  state: TypedState,
  action: Chat2Gen.InboxRefreshPayload | Chat2Gen.LeaveConversationPayload
) => {
  if (!state.config.loggedIn) {
    return
  }
  const onUnverified = function({inbox}) {
    const result: RPCChatTypes.UnverifiedInboxUIItems = JSON.parse(inbox)
    const items: Array<RPCChatTypes.UnverifiedInboxUIItem> = result.items || []
    // We get a subset of meta information from the cache even in the untrusted payload
    const metas = items
      .map(item => Constants.unverifiedInboxUIItemToConversationMeta(item, state.config.username))
      .filter(Boolean)
    // Check if some of our existing stored metas might no longer be valid
    const clearExistingMetas =
      action.type === Chat2Gen.inboxRefresh &&
      ['inboxSyncedClear', 'leftAConversation'].includes(action.payload.reason)
    const clearExistingMessages =
      action.type === Chat2Gen.inboxRefresh && action.payload.reason === 'inboxSyncedClear'
    return Saga.put(
      Chat2Gen.createMetasReceived({clearExistingMessages, clearExistingMetas, fromInboxRefresh: true, metas})
    )
  }

  return RPCChatTypes.localGetInboxNonblockLocalRpcSaga({
    incomingCallMap: {'chat.1.chatUi.chatInboxUnverified': onUnverified},
    params: {
      identifyBehavior: RPCTypes.tlfKeysTLFIdentifyBehavior.chatGui,
      maxUnbox: 0,
      query: Constants.makeInboxQuery([]),
      skipUnverified: false,
    },
    waitingKey: Constants.waitingKeyInboxRefresh,
  })
}

// Service tells us it's done syncing
export const onChatInboxSynced = (syncRes: RPCChatTypes.ChatSyncResult): Saga.Effect =>
  Saga.callUntyped(function*() {
    const state = yield* Saga.selectState()
    const actions = [WaitingGen.createClearWaiting({key: Constants.waitingKeyInboxSyncStarted})]

    switch (syncRes.syncType) {
      // Just clear it all
      case RPCChatTypes.commonSyncInboxResType.clear:
        actions.push(Chat2Gen.createInboxRefresh({reason: 'inboxSyncedClear'}))
        break
      // We're up to date
      case RPCChatTypes.commonSyncInboxResType.current:
        break
      // We got some new messages appended
      case RPCChatTypes.commonSyncInboxResType.incremental: {
        const selectedConversation = Constants.getSelectedConversation(state)
        const username = state.config.username || ''
        const items = (syncRes.incremental && syncRes.incremental.items) || []
        const metas = items.reduce((arr, i) => {
          const meta = Constants.unverifiedInboxUIItemToConversationMeta(i.conv, username)
          if (meta) {
            if (meta.conversationIDKey === selectedConversation) {
              // First thing load the messages
              actions.unshift(
                Chat2Gen.createMarkConversationsStale({
                  conversationIDKeys: [selectedConversation],
                  updateType: RPCChatTypes.notifyChatStaleUpdateType.newactivity,
                })
              )
            }
            arr.push(meta)
          }
          return arr
        }, [])
        // Update new untrusted
        if (metas.length) {
          actions.push(Chat2Gen.createMetasReceived({metas}))
        }
        // Unbox items
        actions.push(
          Chat2Gen.createMetaRequestTrusted({
            conversationIDKeys: items
              .filter(i => i.shouldUnbox)
              .map(i => Types.stringToConversationIDKey(i.conv.convID)),
            force: true,
          })
        )
        break
      }
      default:
        actions.push(Chat2Gen.createInboxRefresh({reason: 'inboxSyncedUnknown'}))
    }

    yield Saga.sequentially(actions)
  })

// Only get the untrusted conversations out
const untrustedConversationIDKeys = (state: TypedState, ids: Array<Types.ConversationIDKey>) =>
  ids.filter(id => state.chat2.metaMap.getIn([id, 'trustedState'], 'untrusted') === 'untrusted')

// We keep a set of conversations to unbox
let metaQueue = I.OrderedSet()
const queueUnboxing = (state, action: Chat2Gen.MetaNeedsUpdatingPayload) => {
  metaQueue = metaQueue.concat(untrustedConversationIDKeys(state, action.payload.conversationIDKeys))
}

// Watch the meta queue and take up to 10 items. Choose the last items first since they're likely still visible
function* unboxLoop(): Generator<any, void, any> {
  const maxToUnboxAtATime = 10
  while (true) {
    // wait for some new ones if there is nothing waiting already
    if (metaQueue.isEmpty()) {
      yield Saga.take(Chat2Gen.metaNeedsUpdating)
    }
    const maybeUnbox = metaQueue.takeLast(maxToUnboxAtATime)
    metaQueue = metaQueue.skipLast(maxToUnboxAtATime)
    const state = yield* Saga.selectState()
    const conversationIDKeys = untrustedConversationIDKeys(state, maybeUnbox.toArray())
    if (conversationIDKeys.length) {
      yield Saga.put(Chat2Gen.createMetaRequestTrusted({conversationIDKeys}))
    }
    yield Saga.delay(100)
  }
}

// Get valid keys that we aren't already loading or have loaded
const rpcMetaRequestConversationIDKeys = (
  action: Chat2Gen.MetaRequestTrustedPayload | Chat2Gen.SelectConversationPayload,
  state: TypedState
) => {
  let keys
  switch (action.type) {
    case Chat2Gen.metaRequestTrusted:
      keys = action.payload.conversationIDKeys
      if (action.payload.force) {
        return keys.filter(Constants.isValidConversationIDKey)
      }
      break
    case Chat2Gen.selectConversation:
      keys = [action.payload.conversationIDKey].filter(Constants.isValidConversationIDKey)
      break
    default:
      Flow.ifFlowComplainsAboutThisFunctionYouHaventHandledAllCasesInASwitch(action)
      throw new Error('Invalid action passed to unboxRows')
  }
  return Constants.getConversationIDKeyMetasToLoad(keys, state.chat2.metaMap)
}

// We want to unbox rows that have scroll into view
const unboxRows = (
  state: TypedState,
  action: Chat2Gen.MetaRequestTrustedPayload | Chat2Gen.SelectConversationPayload
) => {
  if (!state.config.loggedIn) {
    return
  }

  const conversationIDKeys = rpcMetaRequestConversationIDKeys(action, state)
  if (!conversationIDKeys.length) {
    return
  }

  const onUnboxed = function({conv}) {
    const inboxUIItem: RPCChatTypes.InboxUIItem = JSON.parse(conv)
    // We allow empty conversations now since we create them and they're empty now
    const allowEmpty = action.type === Chat2Gen.selectConversation
    const meta = Constants.inboxUIItemToConversationMeta(inboxUIItem, allowEmpty)
    const actions = [
      meta
        ? Saga.put(
            Chat2Gen.createMetasReceived({
              metas: [meta],
              neverCreate: action.type === Chat2Gen.metaRequestTrusted,
            })
          )
        : Saga.put(
            Chat2Gen.createMetaReceivedError({
              conversationIDKey: Types.stringToConversationIDKey(inboxUIItem.convID),
              error: null, // just remove this item, not a real server error
              username: null,
            })
          ),
    ]

    const infoMap = state.users.infoMap
    // We get some info about users also so update that too
    const usernameToFullname = Object.keys(inboxUIItem.fullNames).reduce((map, username) => {
      if (infoMap.get(username, '') !== username) {
        map[username] = inboxUIItem.fullNames[username]
      }
      return map
    }, {})
    if (Object.keys(usernameToFullname).length) {
      actions.push(Saga.put(UsersGen.createUpdateFullnames({usernameToFullname})))
    }
    return Saga.all(actions)
  }

  const onFailed = ({convID, error}) => {
    const conversationIDKey = Types.conversationIDToKey(convID)
    switch (error.typ) {
      case RPCChatTypes.localConversationErrorType.transient:
        logger.info(
          `onFailed: ignoring transient error for convID: ${conversationIDKey} error: ${error.message}`
        )
        break
      default:
        logger.info(`onFailed: displaying error for convID: ${conversationIDKey} error: ${error.message}`)
        return Saga.callUntyped(function*() {
          const state = yield* Saga.selectState()
          yield Saga.put(
            Chat2Gen.createMetaReceivedError({conversationIDKey, error, username: state.config.username})
          )
        })
    }
  }

  return Saga.callUntyped(function*() {
    yield Saga.put(Chat2Gen.createMetaRequestingTrusted({conversationIDKeys}))
    yield RPCChatTypes.localGetInboxNonblockLocalRpcSaga({
      incomingCallMap: {
        'chat.1.chatUi.chatInboxConversation': onUnboxed,
        'chat.1.chatUi.chatInboxFailed': onFailed,
        'chat.1.chatUi.chatInboxUnverified': () => {},
      },
      params: {
        identifyBehavior: RPCTypes.tlfKeysTLFIdentifyBehavior.chatGui,
        query: Constants.makeInboxQuery(conversationIDKeys),
        skipUnverified: true,
      },
      waitingKey: conversationIDKeys.map(Constants.waitingKeyUnboxing),
    })
  })
}

// When we get info on a team we need to unbox immediately so we can get the channel names
const requestTeamsUnboxing = state => {
  const conversationIDKeys = state.chat2.metaMap
    .filter(meta => meta.trustedState === 'untrusted' && meta.teamType === 'big' && !meta.channelname)
    .map(meta => meta.conversationIDKey)
    .toList()
    .toArray()
  return (
    !!conversationIDKeys.length && Promise.resolve(Chat2Gen.createMetaRequestTrusted({conversationIDKeys}))
  )
}

// Helper to handle incoming inbox updates that piggy back on various calls
export const chatActivityToMetasAction = (
  payload: ?{+conv?: ?RPCChatTypes.InboxUIItem}
): Array<TypedActions> => {
  const conv = payload ? payload.conv : null
  const meta = conv && Constants.inboxUIItemToConversationMeta(conv)
  const conversationIDKey = meta
    ? meta.conversationIDKey
    : conv && Types.stringToConversationIDKey(conv.convID)
  const usernameToFullname = (conv && conv.fullNames) || {}
  // We ignore inbox rows that are ignored/blocked/reported or have no content
  const isADelete =
    conv &&
    ([
      RPCChatTypes.commonConversationStatus.ignored,
      RPCChatTypes.commonConversationStatus.blocked,
      RPCChatTypes.commonConversationStatus.reported,
    ].includes(conv.status) ||
      conv.isEmpty)

  // We want to select a different convo if its cause we ignored/blocked/reported. Otherwise sometimes we get that a convo
  // is empty which we don't want to select something else as sometimes we're in the middle of making it!
  const selectSomethingElse = conv ? !conv.isEmpty : false
  return meta
    ? [
        isADelete
          ? Chat2Gen.createMetaDelete({conversationIDKey: meta.conversationIDKey, selectSomethingElse})
          : Chat2Gen.createMetasReceived({metas: [meta]}),
        UsersGen.createUpdateFullnames({usernameToFullname}),
      ]
    : conversationIDKey && isADelete
    ? [Chat2Gen.createMetaDelete({conversationIDKey, selectSomethingElse})]
    : []
}

export function* saga(): Saga.SagaGenerator<any, any> {
  yield Saga.spawn(unboxLoop)
  yield Saga.actionToAction(Chat2Gen.inboxRefresh, inboxRefresh)
  yield Saga.actionToPromise(Chat2Gen.metasReceived, requestTeamsUnboxing)
  yield Saga.actionToPromise(Chat2Gen.metaNeedsUpdating, queueUnboxing)
  yield Saga.actionToAction([Chat2Gen.metaRequestTrusted, Chat2Gen.selectConversation], unboxRows)
}