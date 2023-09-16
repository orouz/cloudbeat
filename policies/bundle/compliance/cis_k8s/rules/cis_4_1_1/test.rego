package compliance.cis_k8s.rules.cis_4_1_1

import data.kubernetes_common.test_data
import data.lib.test

test_violation {
	test.assert_fail(finding) with input as rule_input("10-kubeadm.conf", "700")
}

test_pass {
	test.assert_pass(finding) with input as rule_input("10-kubeadm.conf", "644")
}

test_not_evaluated {
	not finding with input as rule_input("file.txt", "644")
}

rule_input(filename, filemode) = filesystem_input {
	user := "root"
	group := "root"
	filesystem_input = test_data.filesystem_input(filename, filemode, user, group)
}
