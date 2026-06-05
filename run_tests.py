import unittest


if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print('Tests run:', result.testsRun)
    print('Failures:', len(result.failures))
    print('Errors:', len(result.errors))
    raise SystemExit(0 if result.wasSuccessful() else 1)
