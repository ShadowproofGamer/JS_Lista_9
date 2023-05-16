import lista9 as li
import pytest

#zad3


# a
def test_SSHLogEntry_SSHTime():
    obj = li.SSHLogError("Dec 10 11:03:44 LabSZ sshd[25455]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]")
    assert obj.time.month == "Dec"
    assert obj.time.day == "10"
    assert obj.time.hour == "11"
    assert obj.time.minute == "03"
    assert obj.time.second == "44"




# b i
def test_IPv4_raw():
    test_obj = li.IPv4Address("Dec 10 11:03:44 LabSZ sshd[25455]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]" )
    def test_a1():
        assert str(test_obj) == "103.99.0.122"
    def test_a2():
        assert test_obj.ip_addr[0] == "103"
        assert test_obj.ip_addr[1] == "99"
        assert test_obj.ip_addr[2] == "0"
        assert test_obj.ip_addr[3] == "122"
    test_a1()
    test_a2()



# b ii
#tutaj ma byc fail! (bo funkcja nie jest zabezpieczona)
def test_IPv4_invalid():
        test_obj = li.IPv4Address("Dec 10 11:03:44 LabSZ sshd[25455]: error: Received disconnect from 666.777.88.213: 14: No more user authentication methods available. [preauth]" )
        assert test_obj.ip_addr == None
        with pytest.raises(AssertionError):
            def test_a1():
                assert str(test_obj) == "666.777.88.213"
            def test_a2():
                assert test_obj.ip_addr[0] == "666"
                assert test_obj.ip_addr[1] == "777"
                assert test_obj.ip_addr[2] == "88"
                assert test_obj.ip_addr[3] == "213"
            test_a1()
            test_a2()


# b iii
def test_IPv4_none():
    with pytest.raises(Exception):
        assert isinstance(li.IPv4Address("Dec 10 11:03:44 LabSZ sshd[25455]: error: Received disconnect: 14: No more user authentication methods available. [preauth]" ).ip_addr, list)


# c
@pytest.mark.parametrize("type, log, expected_output", [
    (li.SSHLogError, "Dec 10 11:03:44 LabSZ sshd[25455]: error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]", li.SSHLogError),
    (li.SSHLogFailed, ("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"), li.SSHLogFailed),
    (li.SSHLogAccepted, ("Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2"), li.SSHLogAccepted),

])
def test_SSHLogJournal_append(type, log, expected_output):
    obj = li.SSHLogJournal()
    obj.append(repr(type(log)))
    assert isinstance(obj._logs[0], expected_output)

