"""End-to-end test for the raucle-aws-mcp CLI: keygen -> mint -> serve.

Proves the turnkey demo path works: an operator generates an issuer key, mints a
scoped capability, and the server built from those files gates a tool call.
"""

from __future__ import annotations

import json

import pytest

cryptography = pytest.importorskip("cryptography")

from raucle.broker import cli


def _fake_transport(req):
    return 200, b'{"Item":{"id":{"S":"C-1"}}}'


def test_keygen_mint_serve_roundtrip(tmp_path):
    key = tmp_path / "issuer.key.pem"
    pub = tmp_path / "issuer.pub.pem"
    token = tmp_path / "token.json"

    # keygen
    assert cli.main(["keygen", "--issuer", "acme.bank", "--key", str(key), "--pub", str(pub)]) == 0
    assert key.exists()
    assert pub.exists()
    # private key is owner-only
    assert (key.stat().st_mode & 0o077) == 0

    # mint a capability scoped to one DynamoDB table
    assert (
        cli.main(
            [
                "mint",
                "--issuer",
                "acme.bank",
                "--key",
                str(key),
                "--agent-id",
                "agent:kyc-prod",
                "--tool",
                "dynamodb.GetItem",
                "--constraints",
                json.dumps({"allowed_values": {"TableName": ["customers"]}}),
                "--token",
                str(token),
            ]
        )
        == 0
    )
    assert token.exists()

    # build the server from the minted artifacts + env creds
    server = cli.build_server(
        token_path=str(token),
        pub_path=str(pub),
        region="us-east-1",
        env={
            "AWS_ACCESS_KEY_ID": "AKIDEXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        },
    )
    # inject a fake transport so no live AWS call happens
    server._gate._transport = _fake_transport

    # the server handshakes and gates a call end-to-end
    init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init["result"]["serverInfo"]["name"] == "raucle-aws-egress"

    allowed = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "aws.dynamodb.get_item",
                "arguments": {"table": "customers", "key": {"id": {"S": "C-1"}}},
            },
        }
    )
    assert json.loads(allowed["result"]["content"][0]["text"])["Item"]["id"]["S"] == "C-1"

    # a different table is denied by the minted capability
    denied = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "aws.dynamodb.get_item",
                "arguments": {"table": "secret", "key": {"id": {"S": "C-1"}}},
            },
        }
    )
    assert denied["result"]["isError"] is True


def test_serve_requires_aws_credentials(tmp_path):
    key = tmp_path / "k.pem"
    pub = tmp_path / "p.pem"
    token = tmp_path / "t.json"
    cli.main(["keygen", "--issuer", "x", "--key", str(key), "--pub", str(pub)])
    cli.main(
        [
            "mint",
            "--issuer",
            "x",
            "--key",
            str(key),
            "--agent-id",
            "agent:a",
            "--tool",
            "dynamodb.GetItem",
            "--token",
            str(token),
        ]
    )
    with pytest.raises(SystemExit):
        cli.build_server(token_path=str(token), pub_path=str(pub), region=None, env={})
