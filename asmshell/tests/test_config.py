import unittest

from asmshell import config


class TestConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_config: config.Config = config.Config("64", renew=True)  # type: ignore

    def test_config_module_provides_a_default_none_instance(self) -> None:
        self.assertIsNone(config.config)

    def test_config_instances(self) -> None:
        self.assertEqual(
            id(
                config.Config(
                    "64",
                )
            ),
            id(
                config.Config(
                    "64",
                )
            ),
        )
        self.assertNotEqual(
            id(self.sample_config), id(config.Config("64", renew=True))  # type: ignore
        )
