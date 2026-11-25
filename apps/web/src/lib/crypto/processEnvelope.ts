import { fetchSenderDevicePublicKey } from './deviceKeys';
import { decryptAndVerifyEnvelope } from './decrypt';
import { getCachedPlaintext, setCachedPlaintext } from './plaintextCache';
import {
  DecryptError,
  PreLinkError,
  VerificationFailedError,
  type InboundMessage,
  type MessageEditedEvent,
  type UnavailableReason,
} from './types';

export interface EnvelopeInput {
  messageId: string;
  conversationId: string;
  senderId: string;
  senderDeviceId: string | null;
  sequenceNumber: number;
  contentType: string;
  createdAt: string;
  ciphertext: string;
}

function unavailableReasonFromError(err: unknown): UnavailableReason {
  if (err instanceof PreLinkError) return 'pre-link';
  if (err instanceof VerificationFailedError) return 'verification-failed';
  if (err instanceof DecryptError) return 'undecryptable';
  return 'undecryptable';
}

/**
 * Process a single inbound envelope: look up sender key, decrypt, verify, cache.
 */
export async function processInboundEnvelope(
  envelope: EnvelopeInput,
  token: string,
): Promise<InboundMessage> {
  const base: InboundMessage = {
    messageId: envelope.messageId,
    conversationId: envelope.conversationId,
    senderId: envelope.senderId,
    senderDeviceId: envelope.senderDeviceId,
    sequenceNumber: envelope.sequenceNumber,
    contentType: envelope.contentType,
    createdAt: envelope.createdAt,
    status: 'pending',
  };

  const cached = getCachedPlaintext(envelope.messageId);
  if (cached) {
    return { ...base, status: 'decrypted', plaintext: cached };
  }

  if (!envelope.senderDeviceId) {
    return { ...base, status: 'unavailable', unavailableReason: 'pre-link' };
  }

  try {
    const deviceKey = await fetchSenderDevicePublicKey(envelope.senderDeviceId, token);
    const plaintext = await decryptAndVerifyEnvelope(
      envelope.ciphertext,
      envelope.senderDeviceId,
      deviceKey.identityPublicKey,
    );
    setCachedPlaintext(envelope.messageId, plaintext);
    return { ...base, status: 'decrypted', plaintext };
  } catch (err) {
    return {
      ...base,
      status: 'unavailable',
      unavailableReason: unavailableReasonFromError(err),
    };
  }
}

export function sortBySequenceNumber(messages: InboundMessage[]): InboundMessage[] {
  return [...messages].sort((a, b) => a.sequenceNumber - b.sequenceNumber);
}

export function mergeInboundMessage(
  existing: InboundMessage | undefined,
  incoming: InboundMessage,
): InboundMessage {
  if (!existing) return incoming;
  // Prefer a decrypted result over unavailable/pending, but always carry
  // forward edit metadata (isEdited / editedAt) if present on either side.
  const editMeta = {
    ...(existing.isEdited !== undefined && { isEdited: existing.isEdited }),
    ...(existing.editedAt !== undefined && { editedAt: existing.editedAt }),
    ...(incoming.isEdited !== undefined && { isEdited: incoming.isEdited }),
    ...(incoming.editedAt !== undefined && { editedAt: incoming.editedAt }),
  };
  if (existing.status === 'decrypted' && incoming.status !== 'decrypted') {
    return { ...existing, ...editMeta };
  }
  if (incoming.status === 'decrypted') return { ...existing, ...incoming, ...editMeta };
  return { ...existing, ...incoming, ...editMeta };
}

/**
 * Process an inbound `message_edited` event.
 *
 * The new ciphertext is run through the full decrypt/verify pipeline
 * (identical to a normal `processInboundEnvelope` call).  On success:
 *   – the plaintext cache entry is replaced with the new text
 *   – the returned message carries `isEdited: true` and `editedAt`
 *
 * On failure the **existing** message is returned unchanged (preserving any
 * decrypted plaintext and `unavailableReason` already on record).  An
 * `unavailable` result from a failed edit never blanks a previously-readable
 * message, satisfying AC-3.
 */
export async function processMessageEdit(
  event: MessageEditedEvent,
  existing: InboundMessage | undefined,
  token: string,
): Promise<InboundMessage> {
  const base: InboundMessage = existing ?? {
    messageId: event.messageId,
    conversationId: event.conversationId,
    senderId: event.senderId,
    senderDeviceId: event.senderDeviceId,
    sequenceNumber: event.sequenceNumber,
    contentType: event.contentType,
    createdAt: event.createdAt,
    status: 'pending',
  };

  if (!event.senderDeviceId) {
    // Cannot decrypt without a device key — keep the original message intact.
    return { ...base, isEdited: true, editedAt: event.editedAt };
  }

  try {
    const deviceKey = await fetchSenderDevicePublicKey(event.senderDeviceId, token);
    const plaintext = await decryptAndVerifyEnvelope(
      event.ciphertext,
      event.senderDeviceId,
      deviceKey.identityPublicKey,
    );
    // Update plaintext cache so that future renders / search use the new text.
    setCachedPlaintext(event.messageId, plaintext);
    return {
      ...base,
      status: 'decrypted',
      plaintext,
      isEdited: true,
      editedAt: event.editedAt,
      // Clear any prior unavailableReason — the edit decrypted successfully.
      unavailableReason: undefined,
    };
  } catch {
    // Decrypt failed — keep the existing message state so we don't blank it
    // (AC-3).  Just annotate that an edit was attempted.
    return { ...base, isEdited: true, editedAt: event.editedAt };
  }
}
