#!/usr/bin/env python3
"""
unit test suite for gcp_backend_automation.py
TODO:
* add test for each operation
"""
import time
import unittest
target = __import__("gcp_backend_automation")

# For testing purposes, make sure the following are all accurate and present
# The specified backend should contain the instance group
# And that instance group should contain the instance
# This will need to be fixed for the open source body, a lot of it will be broken
# as these test cases were used for the original repo
TEST_FILTER_BACKEND = ['test-backend-1']
# These igs should be in this backend ^^
TEST_FILTER_INSTANCE_GROUP = ['test-ig-1', 'test-ig-2']
# These instances should be in the above IG's ^^
TEST_FILTER_INSTANCE = ['test-instance-1', 'test-instance-2']

TEST_GROUPING_INSTANCE_GROUP = TEST_FILTER_INSTANCE_GROUP[0]

# This infrastrucutre will be used for the health check
# Needs to be seprate from the infra being used for adding and removing
TEST_HEALTH_INSTANCE_GROUP = [TEST_FILTER_INSTANCE_GROUP[0]]
TEST_HEALTH_INSTANCE = [TEST_FILTER_INSTANCE[0]]
# This instance group will be used for testing addding and removing an instance group
# First it will be removed then added. If the add job fails then
# re add it manually before making changes to the test
TEST_ADD_REMOVE_BACKEND = TEST_FILTER_BACKEND
TEST_ADD_REMOVE_IG = [TEST_FILTER_INSTANCE_GROUP[0]]

TEST_FAILED_IG = TEST_FILTER_INSTANCE_GROUP


class TestGcpAutomation(unittest.TestCase):
    """
    Testing suite for gcp_backend_automation.py
    """
    @classmethod
    def setUpClass(cls):
        """
        Getting variables that will be used throughout testing
        """
        cls.args = target.main(['--operation', 'return_args'])
        cls.token = cls.create_token(cls)
        cls.service = target.create_service_object(cls.token)
        cls.all_backends = target.get_all_backends(cls.service)
        cls.run_all = target.run_all(cls.all_backends, cls.service)

    @classmethod
    def tearDownClass(cls):
        """
        Manually closing gcp socket, this isn't great but you'll notice that
        when running this unit test gcp doesnt close the socket for you
        So this is a hack I found
        """
        cls.service._http.close()

    def create_token(self):
        """
        Creating a token
        """
        file = target.find_gcp_file("gcp_svc.json", self.args.gcp_cred)
        cred = target.load_json_credentials(file)

        s_jwt = target.create_signed_jwt(
            cred['private_key'],
            cred['private_key_id'],
            cred['client_email'],
            target.GCE_SCOPES)

        token = target.exchange_jwt_for_access_token(s_jwt)["access_token"]

        return token

    def find_instance(self, infra_snapshot):
        """
        Simply takes an infra_snapshot and checks to see if the
        TEST_FILTER_INSTANCE belongs in the snapshot
        Parameters:
        infra_snapshot (str): list of dictionaries capturing infastructure

        Returns:
        bool : Indicating whether the TEST_FILTER_INSTANCE is within the infra_snapshot
        """
        found_instances = []
        for backends in infra_snapshot:
            if backends['backend_name'] in TEST_FILTER_BACKEND:
                for instance_groups in backends['instance_group_info']:
                    if instance_groups['instance_group_name'] in TEST_FILTER_INSTANCE_GROUP:
                        for instances in TEST_FILTER_INSTANCE:
                            if instances in instance_groups['instances']:
                                found_instances.append(instances)
        found = bool(set(found_instances) == set(TEST_FILTER_INSTANCE))
        return found

    def create_remaining_instance_group(self):
        """
        Create the remainin_instance_group object so that it can be used elsewhere
        """
        # Need fresh all_backends
        local_all_backends = target.get_all_backends(self.service)
        instance_groups_present = target.extract_instance_list_from_all_backends(local_all_backends)
        remaining_instance_groups = target.get_instances_groups_not_in_backends(instance_groups_present,
                                                                                self.service)

        return remaining_instance_groups

    def test_service(self):
        """
        Testing to make sure that the service for GCP can be created and is
        the right type
        """
        module_name = self.service.__class__.__module__
        class_name = self.service.__class__.__name__
        token_class_name = str(module_name + "." + class_name)

        self.assertEqual(token_class_name, 'googleapiclient.discovery.Resource')

    def test_get_all_backends_format(self):
        """
        Testing to make sure that the backend is a list of dicts
        """
        self.assertIs(type(self.all_backends), list)
        first_element = self.all_backends[0]
        self.assertIs(type(first_element), dict)

    def test_get_all_backends_elements(self):
        """
        Testing to make sure that the right keys are present
        """
        first_element = self.all_backends[0]
        backend_keys = list(first_element.keys())
        self.assertEqual(backend_keys, ['backend_name', 'instance_group_info'])
        self.assertEqual(type(first_element['instance_group_info']), list)

        # Make sure permanent backend is in there
        found = False
        for backends in self.all_backends:
            if backends['backend_name'] in TEST_FILTER_BACKEND:
                found = True

        self.assertTrue(found)

    def test_instance_groups_present_and_absent(self):
        """
        Test the function which extracts the instance groups from all_backends
        Then it checks to make sure that you can get the list of instance groups
        Which are not behind a backends
        """
        instance_groups_present = target.extract_instance_list_from_all_backends(self.all_backends)
        self.assertIs(type(instance_groups_present), list)

        count = 0

        for backends in self.all_backends:
            count += len(backends['instance_group_info'])

        self.assertEqual(len(instance_groups_present), count)

        found_instances = []
        for instance_groups in TEST_FILTER_INSTANCE_GROUP:
            if instance_groups in instance_groups_present:
                found_instances.append(instance_groups)

        found = bool(set(found_instances) == set(TEST_FILTER_INSTANCE_GROUP))

        self.assertTrue(found)

        self.assertIs(type(self.create_remaining_instance_group()), list)

    def test_get_instance_for_instance_groups(self):
        """
        Make sure you are able to get a list of instance for an instance group
        """
        found_instances = []
        for backends in self.all_backends:
            if backends['backend_name'] in TEST_FILTER_BACKEND:
                for instance_groups in backends['instance_group_info']:
                    if instance_groups['instance_group_name'] in TEST_FILTER_INSTANCE_GROUP:
                        found_instances.extend(target.get_instances_for_instance_groups(instance_groups,
                                                                                        self.service))
        found = set(TEST_FILTER_INSTANCE).issubset(found_instances)

        self.assertTrue(found)

    def test_run_all(self):
        """
        Test the run_all function which gets entire infra snapshot
        """
        found = False
        infra_snapshot = self.run_all
        found = self.find_instance(infra_snapshot)
        self.run_all = infra_snapshot
        self.assertTrue(found)

        #Return Type
        self.assertEqual(type(infra_snapshot), list)
        self.assertEqual(type(infra_snapshot[0]), dict)

    def test_create_inventory_object(self):
        """
        Test that an inventory object is created
        """
        inventory_object = target.create_inventory_object(self.run_all)
        self.assertIs(type(inventory_object), dict)

        found_instances = []
        for instance_groups in TEST_FILTER_INSTANCE_GROUP:
            for instance in TEST_FILTER_INSTANCE:
                if instance + ".domain.com" in inventory_object[instance_groups]["hosts"]:
                    found_instances.append(instance)
        found = bool(found_instances == TEST_FILTER_INSTANCE)
        self.assertTrue(found)

        #Return Type
        self.assertEqual(type(inventory_object), dict)

    def test_group_inventory_object(self):
        """
        Test that you are able to properly group the inventory object
        Test that your instance group is in the all object
        Test that its in the grouping for the env
        Test that its in the grouping for the client_name
        Test that its in the grouping for client_name and env
        Make Sure its not in the wrong filter
        """
        inventory_object = target.create_inventory_object(self.run_all)
        all_groups = target.group_infra(inventory_object, client_name="", env="")
        self.assertIn(TEST_GROUPING_INSTANCE_GROUP, all_groups)

        env_specific = target.group_infra(inventory_object, client_name="", env="dev")
        self.assertIn(TEST_GROUPING_INSTANCE_GROUP, env_specific)

        self.assertIn(TEST_GROUPING_INSTANCE_GROUP, full_specific)

        wrong_env = target.group_infra(inventory_object, client_name="", env="prod")
        self.assertIsNot(TEST_GROUPING_INSTANCE_GROUP, wrong_env)

    def test_run_backend(self):
        """
        Testing that we can properly filter backends
        """
        infra_snapshot = target.run_backends(self.run_all, TEST_FILTER_BACKEND, self.service)
        self.assertEqual(len(infra_snapshot), 1)

        found = self.find_instance(infra_snapshot)
        self.assertTrue(found)

        #Return Type
        self.assertEqual(type(infra_snapshot), list)


    def test_run_instance_group(self):
        """
        Testing to make sure we can filter by backend
        """
        infra_snapshot = target.run_instance_groups(self.run_all,
                                                    TEST_FILTER_INSTANCE_GROUP,
                                                    self.service)
        self.assertEqual(len(infra_snapshot), 1)

        found = self.find_instance(infra_snapshot)
        self.assertTrue(found)

        #Return Type
        self.assertEqual(type(infra_snapshot), list)

    def test_run_instance(self):
        """
        Testing to make sure we can filter by backend
        """
        infra_snapshot = target.run_instance(self.run_all, TEST_FILTER_INSTANCE, self.service)
        self.assertEqual(len(infra_snapshot), 1)

        found = self.find_instance(infra_snapshot)
        self.assertTrue(found)

        #Return Type
        self.assertEqual(type(infra_snapshot), list)

    def test_run_infra_filter(self):
        """
        Compare the output from the run_infra_filter for each individual
        filter to the call from each function
        """
        # The value from the filter call
        filter_infra_snapshot_all = target.run_infra_filter(self.run_all, self.service)

        filter_infra_snapshot_backend = target.run_infra_filter(self.run_all, self.service,
                                                                TEST_FILTER_BACKEND)

        filter_infra_snapshot_instance_group = target.run_infra_filter(self.run_all, self.service,
                                                                       instance_group_filter=TEST_FILTER_INSTANCE_GROUP)

        filter_infra_snapshot_instance = target.run_infra_filter(self.run_all, self.service,
                                                                 instance_filter=TEST_FILTER_INSTANCE)

        # The instance from the base call
        infra_snapshot_all = self.run_all

        infra_snapshot_backend = target.run_backends(self.run_all, TEST_FILTER_BACKEND,
                                                     self.service)
        infra_snapshot_instance_group = target.run_instance_groups(self.run_all,
                                                                   TEST_FILTER_INSTANCE_GROUP,
                                                                   self.service)

        infra_snapshot_instance = target.run_instance(self.run_all,
                                                      TEST_FILTER_INSTANCE,
                                                      self.service)


        self.assertEqual(filter_infra_snapshot_all, infra_snapshot_all)
        self.assertEqual(filter_infra_snapshot_backend, infra_snapshot_backend)
        self.assertEqual(filter_infra_snapshot_instance_group, infra_snapshot_instance_group)
        self.assertEqual(filter_infra_snapshot_instance, infra_snapshot_instance)

        self.assertEqual(infra_snapshot_backend, infra_snapshot_instance_group)
        self.assertEqual(infra_snapshot_instance, infra_snapshot_instance_group)

    def test_filter_backend_and_instance(self):
        """
        Test to make sure that when filtering on a backend
        and an instance group of that backend
        You get the same object
        """
        infra_snapshot_backend = target.run_backends(self.run_all, TEST_FILTER_BACKEND,
                                                     self.service)
        infra_snapshot_instance_group = target.run_instance_groups(self.run_all,
                                                                   TEST_FILTER_INSTANCE_GROUP,
                                                                   self.service)

        infra_snapshot_instance = target.run_instance(self.run_all,
                                                      TEST_FILTER_INSTANCE,
                                                      self.service)
        self.assertEqual(infra_snapshot_backend, infra_snapshot_instance_group)
        self.assertEqual(infra_snapshot_instance, infra_snapshot_instance_group)

    def test_check_health(self):
        """
        Test the check_health function
        Make sure the instances in TEST_FILTER_INSTANCES are healthy
        """
        local_all_backends = target.get_all_backends(self.service)
        local_run_all = target.run_all(local_all_backends, self.service)
        infra_snapshot = target.run_backends(local_run_all, TEST_FILTER_BACKEND, self.service)
        for backends in infra_snapshot:
            if backends['backend_name'] in TEST_FILTER_BACKEND:
                infra_snapshot_health = target.check_healthy_instance_groups(backends,
                                                                             self.service)

        found_instances = []
        for instance in TEST_HEALTH_INSTANCE:
            if instance in infra_snapshot_health[0]:
                found_instances.append(instance)
        found = bool(set(found_instances) == set(TEST_HEALTH_INSTANCE))
        self.assertTrue(found)

        self.assertEqual(len(infra_snapshot_health[1]), 0)
        #Return Type
        self.assertEqual(type(infra_snapshot_health), tuple)

    def test_run_check_health(self):
        """
        Test the run_health_check function
        """
        local_all_backends = target.get_all_backends(self.service)
        local_run_all = target.run_all(local_all_backends, self.service)
        infra_snapshot = target.run_instance_groups(local_run_all,
                                                    TEST_HEALTH_INSTANCE_GROUP,
                                                    self.service)
        infra_snapshot_health = target.run_check_health(infra_snapshot, self.service)
        self.assertGreater(len(infra_snapshot_health[0]['healthy_nodes']), 0)
        self.assertEqual(len(infra_snapshot_health[0]['unhealthy_nodes']), 0)

    ####### TESTING ADDING AND REMOVING ##########
    def test_add_and_remove(self):
        """
        This test will ensure that the instance_group is properly removed
        and added to the load balancer

        It will first check to make sure that the instance lives behind the
        load balancer, if it does then it will remove then add it

        If it does not live behind a load balancer, it will add then remove it
        """
        found = False
        for backend in self.all_backends:
            for instance_group in backend['instance_group_info']:
                if instance_group['instance_group_name'] in TEST_ADD_REMOVE_IG:
                    found = True
                    break
            if found:
                break

        if found:
            remove_change_request = target.run_remove_instance_group(self.all_backends,
                                                                     TEST_ADD_REMOVE_IG,
                                                                     self.service)
            time.sleep(30)


            add_change_request = target.run_add_instance_group(TEST_ADD_REMOVE_IG,
                                                               TEST_ADD_REMOVE_BACKEND,
                                                               self.create_remaining_instance_group(),
                                                               self.service)
            time.sleep(30)
        else:
            print("MAKE SURE TO FOLLOW INSTRUCTIONS")
            print(f"{TEST_ADD_REMOVE_IG} needs to be in {TEST_ADD_REMOVE_BACKEND}")

        self.assertEqual(remove_change_request['status'], 'success')
        self.assertEqual(add_change_request['status'], 'success')


    def test_fail_removing_instance_group(self):
        """
        Make sure the following causes failures
        When more than one instance group is specified
        When the instance group doesnt belong to backend
        """
        # Fail because youre trying to remove 2 instance groups
        fail_multi_instance_group = target.run_remove_instance_group(self.all_backends,
                                                                     TEST_FILTER_INSTANCE_GROUP,
                                                                     self.service)
        self.assertEqual(fail_multi_instance_group['status'], 'failure')
#
        # Remove the instance group from the backend
        target.run_remove_instance_group(self.all_backends,
                                         TEST_ADD_REMOVE_IG,
                                         self.service)
        time.sleep(10)
        # Fail because this instance group doesn't belong to a backend
        fail_not_in_backend = target.run_remove_instance_group(self.all_backends,
                                                               TEST_ADD_REMOVE_IG,
                                                               self.service)
        self.assertEqual(fail_not_in_backend['status'], 'failure')

        #Make sure you can add it back
        time.sleep(10)
        add_change_request = target.run_add_instance_group(TEST_ADD_REMOVE_IG,
                                                           TEST_ADD_REMOVE_BACKEND,
                                                           self.create_remaining_instance_group(),
                                                           self.service)
        time.sleep(10)
        self.assertEqual(add_change_request['status'], 'success')

    def test_fail_adding_instance_group(self):
        """
        Make sure the following cases causes failures
        Adding instance group which already belongs to a backend
        Adding more than one instance group
        Passing too many backends to the function
        Passing instance groups which have wrong aiport code
        Passing instance group that doesnt exist
        """
        add_to_existing = target.run_add_instance_group(TEST_ADD_REMOVE_IG,
                                                        TEST_ADD_REMOVE_BACKEND,
                                                        self.create_remaining_instance_group(),
                                                        self.service)
        self.assertEqual(add_to_existing['status'], 'failure')

        adding_two_instance_groups = target.run_add_instance_group(TEST_ADD_REMOVE_IG,
                                                                   TEST_ADD_REMOVE_BACKEND,
                                                                   self.create_remaining_instance_group(),
                                                                   self.service)
        self.assertEqual(adding_two_instance_groups['status'], "failure")

        two_backends = ["Bullshit-backend-1"]
        two_backends.extend(TEST_ADD_REMOVE_BACKEND)
        adding_two_backends = target.run_add_instance_group(TEST_ADD_REMOVE_IG,
                                                            two_backends,
                                                            self.create_remaining_instance_group(),
                                                            self.service)
        self.assertEqual(adding_two_backends['status'], 'failure')

        # Try to add two instance groups
        adding_two_instance_groups = target.run_add_instance_group(TEST_FAILED_IG,
                                                                   TEST_ADD_REMOVE_BACKEND,
                                                                   self.create_remaining_instance_group(),
                                                                   self.service)
        self.assertEqual(adding_two_instance_groups['status'], 'failure')

        #Fail when the instance group doesnt exist
        fake_instance_group = target.run_add_instance_group(["Fake_instance_group-1"],
                                                            TEST_ADD_REMOVE_BACKEND,
                                                            self.create_remaining_instance_group(),
                                                            self.service)
        self.assertEqual(fake_instance_group['status'], 'failure')

if __name__ == '__main__':
    unittest.main()
