"""Native refresh rotation scenarios, using the shared Cognito probe recorder."""
from pathlib import Path
import secrets
import time


def rotation_slice(evidence, record, required, *, secret_hash):
    evidence["scope"] = "One owned pool upgraded from Lite to Essentials and one synthetic active user; refresh rotation, grace, client secrets and revocation; no messages, devices or Lambda triggers"
    evidence["bounds"] = {"max_pools": 1, "max_requests": 120, "max_users_per_pool": 1, "max_clients_per_pool": 8, "grace_wait_seconds": 5}
    evidence["documentation"].extend([
        "https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html",
        "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetTokensFromRefreshToken.html"])
    evidence["slice_source"] = {"path": str(Path(__file__)), "text": Path(__file__).read_text()}
    pool = required("rotation-create-pool", "CreateUserPool", {"PoolName": evidence["prefix"], "UserPoolTier": "LITE"})["UserPool"]["Id"]
    flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH"]
    base = {"UserPoolId": pool, "ExplicitAuthFlows": flows}

    def create(label, **extra):
        return required(label, "CreateUserPoolClient", dict(base, ClientName=label, **extra))["UserPoolClient"]

    user = {"UserPoolId": pool, "Username": "rotation-user"}
    password = "FinalA1!" + secrets.token_hex(12)
    required("rotation-create-user", "AdminCreateUser", dict(user, TemporaryPassword="TempA1!" + secrets.token_hex(12), MessageAction="SUPPRESS"))
    required("rotation-set-password", "AdminSetUserPassword", dict(user, Password=password, Permanent=True))
    plain = create("rotation-create-plain", ExplicitAuthFlows=flows + ["ALLOW_REFRESH_TOKEN_AUTH"])
    lite = required("rotation-lite-login", "InitiateAuth", {"ClientId": plain["ClientId"], "AuthFlow": "USER_PASSWORD_AUTH",
        "AuthParameters": {"USERNAME": user["Username"], "PASSWORD": password}}, "unsigned")["AuthenticationResult"]
    record("rotation-lite-refresh-api", "GetTokensFromRefreshToken", {"ClientId": plain["ClientId"], "RefreshToken": lite["RefreshToken"]}, "unsigned")
    record("rotation-lite-unavailable", "CreateUserPoolClient", dict(base, ClientName="lite-unavailable", RefreshTokenRotation={"Feature": "ENABLED"}))
    required("rotation-upgrade-tier", "UpdateUserPool", {"UserPoolId": pool, "UserPoolTier": "ESSENTIALS"})
    required("rotation-describe-upgraded-tier", "DescribeUserPool", {"UserPoolId": pool})
    zero = create("rotation-create-zero", RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 0})
    grace = create("rotation-create-grace", RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 4})
    private = create("rotation-create-private", GenerateSecret=True, RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 0})
    record("rotation-conflicting-flow", "CreateUserPoolClient", dict(base, ClientName="conflicting-flow", ExplicitAuthFlows=flows + ["ALLOW_REFRESH_TOKEN_AUTH"], RefreshTokenRotation={"Feature": "ENABLED"}))
    record("rotation-default-flows", "CreateUserPoolClient", {"UserPoolId": pool, "ClientName": "default-flows", "RefreshTokenRotation": {"Feature": "ENABLED"}})
    record("rotation-disabled-grace", "CreateUserPoolClient", dict(base, ClientName="disabled-grace", RefreshTokenRotation={"Feature": "DISABLED", "RetryGracePeriodSeconds": 4}))
    no_revoke = record("rotation-revocation-disabled", "CreateUserPoolClient", dict(base, ClientName="revocation-disabled", EnableTokenRevocation=False, RefreshTokenRotation={"Feature": "ENABLED"}))

    def login(label, client):
        parameters = {"USERNAME": user["Username"], "PASSWORD": password}
        if "ClientSecret" in client:
            parameters["SECRET_HASH"] = secret_hash(user["Username"], client["ClientId"], client["ClientSecret"])
        return required(label, "InitiateAuth", {"ClientId": client["ClientId"], "AuthFlow": "USER_PASSWORD_AUTH", "AuthParameters": parameters}, "unsigned")["AuthenticationResult"]

    def refresh(label, client, token, *, mode="unsigned", include_secret=True, **extra):
        parameters = {"ClientId": client["ClientId"], "RefreshToken": token}
        if include_secret and "ClientSecret" in client:
            parameters["ClientSecret"] = client["ClientSecret"]
        parameters.update(extra)
        return record(label, "GetTokensFromRefreshToken", parameters, mode)

    def tokens(result):
        if result["code"] != "Success":
            raise RuntimeError("Expected refresh success, got " + result["code"])
        return result["output"]["AuthenticationResult"]

    def get(label, token):
        return record(label, "GetUser", {"AccessToken": token}, "unsigned")

    def revoke(label, client, token):
        parameters = {"ClientId": client["ClientId"], "Token": token}
        if "ClientSecret" in client:
            parameters["ClientSecret"] = client["ClientSecret"]
        return record(label, "RevokeToken", parameters, "unsigned")

    def configure_rotation(label, client, enabled):
        config = dict(base, ClientId=client["ClientId"], RefreshTokenRotation={"Feature": "ENABLED" if enabled else "DISABLED"})
        if enabled:
            config["RefreshTokenRotation"]["RetryGracePeriodSeconds"] = 0
        else:
            config["ExplicitAuthFlows"] = flows + ["ALLOW_REFRESH_TOKEN_AUTH"]
        return required(label, "UpdateUserPoolClient", config)

    initial_plain = login("rotation-plain-login", plain)
    for mode in ("unsigned", "signed", "invalid-signature", "malformed-authorization"):
        refresh("rotation-plain-" + mode, plain, initial_plain["RefreshToken"], mode=mode)
    refresh("rotation-plain-metadata", plain, initial_plain["RefreshToken"], ClientMetadata={"probe": "no-trigger"})
    refresh("rotation-plain-extra-secret", plain, initial_plain["RefreshToken"], ClientSecret="WrongSecret01234567890123456789")
    refresh("rotation-wrong-client", zero, initial_plain["RefreshToken"])
    refresh("rotation-invalid-token", plain, "invalid-refresh-token")
    refresh("rotation-missing-client", {"ClientId": "a" * 26}, initial_plain["RefreshToken"])

    first = login("rotation-zero-login", zero)
    independent = login("rotation-independent-login", zero)
    record("rotation-legacy-flow-rejected", "InitiateAuth", {"ClientId": zero["ClientId"], "AuthFlow": "REFRESH_TOKEN_AUTH", "AuthParameters": {"REFRESH_TOKEN": first["RefreshToken"]}}, "unsigned")
    child = tokens(refresh("rotation-zero-first", zero, first["RefreshToken"]))
    get("rotation-old-access-after-rotation", first["AccessToken"])
    refresh("rotation-zero-parent-reuse", zero, first["RefreshToken"])
    next_child_result = refresh("rotation-child-after-parent-reuse", zero, child["RefreshToken"])
    next_child = tokens(next_child_result) if next_child_result["code"] == "Success" else child
    revoke("rotation-revoke-old-parent", zero, first["RefreshToken"])
    get("rotation-parent-access-after-revoke", first["AccessToken"])
    get("rotation-child-access-after-parent-revoke", child["AccessToken"])
    refresh("rotation-child-refresh-after-parent-revoke", zero, next_child["RefreshToken"])
    independent_child = tokens(refresh("rotation-independent-refresh", zero, independent["RefreshToken"]))
    revoke("rotation-revoke-child", zero, independent_child["RefreshToken"])
    get("rotation-independent-parent-access-after-child-revoke", independent["AccessToken"])
    get("rotation-independent-child-access-after-revoke", independent_child["AccessToken"])

    grace_parent = login("rotation-grace-login", grace)
    grace_first = tokens(refresh("rotation-grace-first", grace, grace_parent["RefreshToken"]))
    first_finished = time.monotonic()
    time.sleep(2)
    grace_retry_result = refresh("rotation-grace-retry", grace, grace_parent["RefreshToken"])
    if grace_retry_result["code"] == "Success":
        grace_retry = tokens(grace_retry_result)
        evidence["rotation_comparisons"] = {"grace_retry_reuses_refresh_token": grace_retry["RefreshToken"] == grace_first["RefreshToken"]}
    remaining = first_finished + 5 - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
    refresh("rotation-grace-parent-after-deadline", grace, grace_parent["RefreshToken"])
    refresh("rotation-grace-first-child-after-deadline", grace, grace_first["RefreshToken"])
    if grace_retry_result["code"] == "Success":
        refresh("rotation-grace-retry-child-after-deadline", grace, grace_retry["RefreshToken"])

    retry_parent = login("rotation-retry-replacement-login", grace)
    retry_first = tokens(refresh("rotation-retry-replacement-first", grace, retry_parent["RefreshToken"]))
    refresh("rotation-retry-replacement-parent", grace, retry_parent["RefreshToken"])
    refresh("rotation-displaced-child-immediate", grace, retry_first["RefreshToken"])
    chain_parent = login("rotation-chain-login", grace)
    chain_first = tokens(refresh("rotation-chain-first", grace, chain_parent["RefreshToken"]))
    refresh("rotation-chain-second", grace, chain_first["RefreshToken"])
    refresh("rotation-chain-ancestor-within-original-grace", grace, chain_parent["RefreshToken"])
    refresh("rotation-chain-previous-within-grace", grace, chain_first["RefreshToken"])

    secret_tokens = login("rotation-private-login", private)
    refresh("rotation-private-missing-secret", private, secret_tokens["RefreshToken"], include_secret=False)
    refresh("rotation-private-wrong-secret", private, secret_tokens["RefreshToken"], ClientSecret="WrongSecret01234567890123456789")
    private_child = tokens(refresh("rotation-private-valid-secret", private, secret_tokens["RefreshToken"]))
    revoke("rotation-private-revoke-child", private, private_child["RefreshToken"])
    refresh("rotation-private-after-revoke", private, private_child["RefreshToken"])

    configure_rotation("rotation-enable-existing-client", plain, True)
    enabled_child = tokens(refresh("rotation-existing-session-after-enable", plain, initial_plain["RefreshToken"]))
    configure_rotation("rotation-disable-existing-client", plain, False)
    disabled_tokens = tokens(refresh("rotation-session-after-disable", plain, enabled_child["RefreshToken"]))
    refresh("rotation-old-parent-after-disable", plain, initial_plain["RefreshToken"])
    refresh("rotation-session-after-disable-repeat", plain, enabled_child["RefreshToken"])
    record("rotation-session-after-disable-legacy", "InitiateAuth", {"ClientId": plain["ClientId"], "AuthFlow": "REFRESH_TOKEN_AUTH",
        "AuthParameters": {"REFRESH_TOKEN": enabled_child["RefreshToken"]}}, "unsigned")
    configure_rotation("rotation-reenable-existing-client", plain, True)
    reenabled_child = tokens(refresh("rotation-session-after-reenable", plain, enabled_child["RefreshToken"]))
    configure_rotation("rotation-disable-client-again", plain, False)
    disabled_again = tokens(refresh("rotation-session-after-second-disable", plain, reenabled_child["RefreshToken"]))
    revoke("rotation-revoke-ancestor-while-disabled", plain, initial_plain["RefreshToken"])
    get("rotation-disabled-old-access-after-ancestor-revoke", disabled_tokens["AccessToken"])
    get("rotation-disabled-current-access-after-ancestor-revoke", disabled_again["AccessToken"])
    refresh("rotation-disabled-refresh-after-ancestor-revoke", plain, reenabled_child["RefreshToken"])
    revoke("rotation-revoke-current-after-ancestor", plain, reenabled_child["RefreshToken"])
    get("rotation-disabled-old-access-after-current-revoke", disabled_tokens["AccessToken"])
    get("rotation-disabled-current-access-after-current-revoke", disabled_again["AccessToken"])
    other_parent = login("rotation-disabled-child-revoke-login", plain)
    configure_rotation("rotation-enable-child-revoke-client", plain, True)
    other_child = tokens(refresh("rotation-child-revoke-rotated", plain, other_parent["RefreshToken"]))
    configure_rotation("rotation-disable-child-revoke-client", plain, False)
    other_disabled = tokens(refresh("rotation-child-revoke-disabled", plain, other_child["RefreshToken"]))
    revoke("rotation-revoke-child-while-disabled", plain, other_child["RefreshToken"])
    get("rotation-root-access-after-disabled-child-revoke", other_parent["AccessToken"])
    get("rotation-rotated-access-after-disabled-child-revoke", other_child["AccessToken"])
    get("rotation-disabled-access-after-disabled-child-revoke", other_disabled["AccessToken"])
    refresh("rotation-refresh-after-disabled-child-revoke", plain, other_child["RefreshToken"])
    required("rotation-global-signout-mixed-origins", "AdminUserGlobalSignOut", user)
    get("rotation-disabled-old-access-after-global-signout", disabled_tokens["AccessToken"])
    get("rotation-disabled-current-access-after-global-signout", disabled_again["AccessToken"])
    if no_revoke["code"] == "Success":
        client = no_revoke["output"]["UserPoolClient"]
        session = login("rotation-revocation-disabled-login", client)
        rotated = tokens(refresh("rotation-revocation-disabled-refresh", client, session["RefreshToken"]))
        revoke("rotation-revocation-disabled-revoke", client, rotated["RefreshToken"])
        get("rotation-revocation-disabled-access", rotated["AccessToken"])
    no_revoke_plain = create("rotation-create-no-revocation-plain", EnableTokenRevocation=False, ExplicitAuthFlows=flows + ["ALLOW_REFRESH_TOKEN_AUTH"])
    plain_session = login("rotation-no-revocation-plain-login", no_revoke_plain)
    record("rotation-no-revocation-legacy-refresh", "InitiateAuth", {"ClientId": no_revoke_plain["ClientId"], "AuthFlow": "REFRESH_TOKEN_AUTH",
        "AuthParameters": {"REFRESH_TOKEN": plain_session["RefreshToken"]}}, "unsigned")
    refresh("rotation-no-revocation-plain-refresh", no_revoke_plain, plain_session["RefreshToken"])
    refresh("rotation-device-key-without-tracking", no_revoke_plain, plain_session["RefreshToken"],
        DeviceKey="us-east-1_11111111-1111-1111-1111-111111111111")
    tier_session = login("rotation-before-downgrade-login", zero)
    record("rotation-downgrade-with-enabled-clients", "UpdateUserPool", {"UserPoolId": pool, "UserPoolTier": "LITE"})
    required("rotation-describe-after-downgrade", "DescribeUserPool", {"UserPoolId": pool})
    required("rotation-describe-client-after-downgrade", "DescribeUserPoolClient", {"UserPoolId": pool, "ClientId": zero["ClientId"]})
    refresh("rotation-refresh-after-downgrade", zero, tier_session["RefreshToken"])
    evidence["completed_at"] = evidence["observations"][-1]["finished_at"]
