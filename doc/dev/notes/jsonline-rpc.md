JSONLINES RPC PROTOCOL
======================

I propose the following protocol for RPC to Arti.

1. We use JSON-RPC 2.0.  https://www.jsonrpc.org/specification

2. JSON-RPC is transport-agnostic.
We define the following trivial transport protocol,
which we will call "jsonlines-rpc":

  * Connect to a local socket (AF_UNIX on Unix, "named pipes" on Windows)

  * Send RPC request(s) in JSON format.

  * Server sends respons(es) in JSON format, but jsonlines.
    That is, one JSON document per line.
    https://jsonlines.org/.

  * Client may pipeline requests.
    Server may reply out of order.
    So a client which pipelines must us the `id` field to correlate responses.

3. Event stream extension

 * The *server* may send JSON-RPC Notifications (section 4.1)

 * It will do this on a connection only if requested by the client on that connection

4. Access control will be based on a password or API token passed in each request.
   In the future perhaps there will be TLS or something.

5. Statefulness:
   Most requests will be stateless.
   Advanced features might involve per-connection server-side state.
   Event streams involve per-connection server-side state.

Properties of this protocol
===========================

Any JSON-RPC client library that supports local socket connections can be used,
unless event streams are required.

A JSON-RPC client library is not required.
A client can simply open the socket and print JSON objects into it,
and use the langauge's "read line from stream" function to receive responses.

A JSON object *parsing* library is required for all but the most
simple use cases.  A JSON object *constructing* library would be useful.
These are extremely widely available.

A client that wants to receive an event stream and also wants to use a
JSON-RPC library that doesn't support the event stream extension,
could use the JSON-RPC library for commands/responses on one
connection, and a simple line-based approach on a separate client
connection for the event stream.

A client written in a dynamic language like Python does not need a
schema for the protocol.  That is, it can parse responses without
having to import into its source tree anything from the Arti project.

Implementing the server side involves unquoted-bracket-counting in
order to deframe the client's requests.  This is tolerable; the benfit
is the ability to use any JSON-RPC client, since it avoids imposing
the requirement that the requests be one per line.

The protocol is textual and can be dumped directly by hand.  One might
even interact directly with the protocol server on a terminal.

Alternatives
============

I did some searching.

Good marshalling and unmarshalling code is available for a bewildering
array of data formats.  JSON, messagepack, BSON, protobuf, XML, you
name it.

But we want some kind of transport/framing protocol.

 * The JSON-RPC spec itself doesn't offer a framing protocol,
   but it is apparently common to offer it over sockets in
   a "connect, send request, await reply, close" mode.
   This proposal is compatible with such a client implementation.
   Such a library can't be used for event streams.

 * Microsoft's Language Server Protocol uses a JSON-RPC variant
   that adds HTTP-style Content-Length headers for framing.
   This seems otiose, and implementations separate from LSP implementations
   don't seem readily available.

 * zeromq has a messagepack-based RPC system.  It seems quite heavyweight.
   Heartbeats and do on.

 * grpc uses protobufs.  Unfortunately, you cannot parse a protobuf binary
   message unless you have the protocol schema.  This means that if we used
   protobuf, client programs would need to take our IDL and compile it in
   their own code using the protobuf IDL compiler.  There are other reasons
   not to like protobufs, eg see
     https://reasonablypolymorphic.com/blog/protos-are-wrong/

 * There are a number of systems based on HTTP.  HTTP (all variants)
   are quite bad because they lack useful guarantees about connection
   lifetime.  Clients must have very complex state management code
   (especially if they are trying to collect event streams).
   In practice many clients don't do this right, leading to race bugs
   (eg lost events) which occur only under high load or unusual conditions.
