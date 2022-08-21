import unittest

from asmshell import config


class TestConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_config = config.Config(renew=True)

    def test_config_module_provides_a_default_instance(self) -> None:
        self.assertIsNotNone(config.config)

    def test_config_instances(self) -> None:
        self.assertEqual(id(config.Config()), id(config.Config()))
        self.assertNotEqual(
            id(self.sample_config), id(config.Config(renew=True))
        )
