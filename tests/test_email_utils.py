from services.email_utils import canonicalize_email, is_disposable


def test_gmail_dots_and_plus_give_same_canonical():
    assert canonicalize_email("juan.lopez+x@gmail.com") == canonicalize_email("juanlopez@gmail.com")
    assert canonicalize_email("juanlopez@gmail.com") == "juanlopez@gmail.com"


def test_googlemail_becomes_gmail():
    assert canonicalize_email("juan.lopez@googlemail.com") == "juanlopez@gmail.com"


def test_other_domain_keeps_dots_and_plus():
    assert canonicalize_email("juan.lopez+x@empresa.com") == "juan.lopez+x@empresa.com"


def test_uppercase_and_spaces():
    assert canonicalize_email("  Juan.Lopez+X@GMAIL.COM  ") == "juanlopez@gmail.com"
    assert canonicalize_email("  Juan.Lopez+X@Empresa.COM ") == "juan.lopez+x@empresa.com"


def test_is_disposable():
    assert is_disposable("mailinator.com") is True
    assert is_disposable("gmail.com") is False
