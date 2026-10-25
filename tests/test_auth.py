from app.web.auth import hash_password, verify_password


def test_password_hash_round_trip_and_wrong_password() -> None:
    encoded = hash_password("correct horse battery staple", iterations=10_000)
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)
    assert not verify_password("correct horse battery staple", "malformed")
