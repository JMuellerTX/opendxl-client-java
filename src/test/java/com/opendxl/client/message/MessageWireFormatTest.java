package com.opendxl.client.message;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Verifies that messages keep the exact DXL wire format. The reference vectors were produced with the original
 * msgpack 0.6.7 based implementation of the client (version 0.2.9) and cover the "raw" length boundaries
 * (fixraw, raw16, raw32), signed/unsigned integer encodings and the string collections of the message header.
 */
public class MessageWireFormatTest {

    /**
     * The source client identifier used in all reference vectors
     */
    private static final String SOURCE_CLIENT_ID = "{11111111-2222-3333-4444-555555555555}";

    /**
     * Loads a reference vector
     *
     * @param name The name of the vector
     * @return The bytes of the vector
     * @throws IOException If the vector can not be read
     */
    private static byte[] vector(final String name) throws IOException {
        try (InputStream in = MessageWireFormatTest.class.getResourceAsStream("wireformat/" + name + ".bin")) {
            assertNotNull("Missing reference vector: " + name, in);
            return IOUtils.toByteArray(in);
        }
    }

    /**
     * Parses the vector, verifies the common header fields and checks that re-packing produces identical bytes
     *
     * @param name The name of the vector
     * @return The parsed message
     * @throws IOException If an I/O error occurs
     */
    private static Message roundTrip(final String name) throws IOException {
        final byte[] bytes = vector(name);
        final Message message = Message.fromBytes(bytes);
        assertEquals(Message.MESSAGE_VERSION, message.getVersion());
        assertEquals(SOURCE_CLIENT_ID, message.getSourceClientId());
        assertArrayEquals("Re-packed bytes differ for " + name, bytes, message.toBytes());
        return message;
    }

    /**
     * Verifies the fields of the reference request (the header collections have more than one entry, so the
     * re-packed bytes can legitimately differ in their order)
     *
     * @param request The request to check
     */
    private static void assertReferenceRequest(final Request request) {
        assertEquals(SOURCE_CLIENT_ID, request.getSourceClientId());
        assertEquals("/mcafee/client/{66666666-7777-8888-9999-000000000000}", request.getReplyToTopic());
        assertEquals("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", request.getServiceId());
        assertArrayEquals(payload(31), request.getPayload());
        assertEquals(2, request.getOtherFields().size());
        assertEquals("v1", request.getOtherFields().get("k1"));
        assertEquals("value-€", request.getOtherFields().get("key-äö"));
        assertEquals("{tenant-1}", request.getSourceTenantGuid());
        assertEquals(new HashSet<>(Arrays.asList("{t2}", "{t3}")), request.getDestTenantGuids());
        assertEquals("{instance-1}", request.getSourceClientInstanceId());
    }

    /**
     * Builds the deterministic payload used by the reference vectors
     *
     * @param size The payload size
     * @return The payload
     */
    private static byte[] payload(final int size) {
        final byte[] result = new byte[size];
        for (int i = 0; i < size; i++) {
            result[i] = (byte) (i * 7 + 3);
        }
        return result;
    }

    /**
     * Tests that a request with all header fields is parsed and re-packed identically
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testRequestWithHeaderFields() throws Exception {
        final byte[] bytes = vector("request31");
        final Message message = Message.fromBytes(bytes);
        assertTrue(message instanceof Request);
        assertEquals(Message.MESSAGE_VERSION, message.getVersion());
        assertReferenceRequest((Request) message);
        // Re-packing must produce the same amount of bytes and parse to the same message
        final byte[] repacked = message.toBytes();
        assertEquals(bytes.length, repacked.length);
        assertReferenceRequest((Request) Message.fromBytes(repacked));
    }

    /**
     * Tests that a response is parsed and re-packed identically
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testResponse() throws Exception {
        final Message message = roundTrip("response32");
        assertTrue(message instanceof Response);
        assertArrayEquals(payload(32), message.getPayload());
        assertEquals("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", ((Response) message).getServiceId());
    }

    /**
     * Tests the empty payload and the raw32 payload encoding
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testEventPayloadBoundaries() throws Exception {
        assertArrayEquals(payload(0), roundTrip("event0").getPayload());
        assertArrayEquals(payload(65536), roundTrip("event65536").getPayload());
    }

    /**
     * Tests the integer encodings of the error code and the raw16/uint8 boundaries
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testErrorResponseIntegerEncodings() throws Exception {
        assertEquals(Integer.MIN_VALUE, ((ErrorResponse) roundTrip("errorMin")).getErrorCode());
        assertEquals("Fabric error é", ((ErrorResponse) roundTrip("errorMin")).getErrorMessage());
        assertEquals(200, ((ErrorResponse) roundTrip("error200")).getErrorCode());
        assertArrayEquals(payload(65535), roundTrip("error200").getPayload());
        assertEquals(70000, ((ErrorResponse) roundTrip("error70000")).getErrorCode());
        assertArrayEquals(payload(255), roundTrip("error70000").getPayload());
        assertEquals(-100, ((ErrorResponse) roundTrip("errorNeg100")).getErrorCode());
        assertArrayEquals(payload(256), roundTrip("errorNeg100").getPayload());
    }

    /**
     * Tests that newly created messages use the legacy raw format (no str8/bin types)
     *
     * @throws Exception If an error occurs
     */
    @Test
    public void testNewMessagesUseLegacyRawFormat() throws Exception {
        final Event event = new Event(SOURCE_CLIENT_ID, "/test/event");
        event.setPayload(payload(100));
        final byte[] bytes = event.toBytes();
        // version (fixint 3), type (fixint 2), then the 38 character message id as raw16 (0xda, length)
        assertEquals(3, bytes[0]);
        assertEquals(Message.MESSAGE_TYPE_EVENT, bytes[1]);
        assertEquals((byte) 0xda, bytes[2]);
        assertEquals(0, bytes[3]);
        assertEquals(event.getMessageId().length(), bytes[4]);
        // A payload of 100 bytes must use raw16 (0xda), never str8 (0xd9) or bin8 (0xc4)
        boolean found = false;
        for (int i = 0; i < bytes.length - 2; i++) {
            if (bytes[i] == (byte) 0xda && bytes[i + 1] == 0 && bytes[i + 2] == 100) {
                found = true;
            }
        }
        assertTrue("payload not encoded as raw16", found);
        assertEquals(event.getMessageId(), Message.fromBytes(bytes).getMessageId());
    }
}
