# Project_Assessment
Company assessment

Sample usage:

./scan_stig compare 181220232348060003 181220232351020004

Summary statistics ID 1

    ID      : 181220232348060003
    Date        : 2023-12-18 23:48:06
    System Score    : 80.615921
    Total Rules : 119
        Passed  : 74
        Failed  : 45

Summary statistics ID 2

    ID      : 181220232351020004
    Date        : 2023-12-18 23:51:02
    System Score    : 80.615921
    Total Rules : 121
        Passed  : 75
        Failed  : 46

Summary statistics

    Extra rules ID 1
        None

    Extra rules ID 2
        Rule    : xccdf_org.ssgproject.content_rule_aide_verify_ext_attributes
        Rule    : xccdf_org.ssgproject.content_rule_package_crypto-policies_installed

    Unmatching results for the same rule
        Rule    : xccdf_org.ssgproject.content_rule_configure_kerberos_crypto_policy
        ID 1    : pass
        ID 2    : fail

        Rule    : xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_openssh_conf_crypto_policy
        ID 1    : fail
        ID 2    : pass