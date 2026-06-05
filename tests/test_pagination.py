import unittest

from pagination import ELLIPSIS, build_page_items


class PaginationTests(unittest.TestCase):
    def test_single_page(self):
        self.assertEqual(build_page_items(1, 1), [1])

    def test_small_range(self):
        self.assertEqual(build_page_items(2, 4), [1, 2, 3, 4])

    def test_start_window_includes_last_page(self):
        self.assertEqual(build_page_items(2, 10), [1, 2, 3, ELLIPSIS, 10])

    def test_end_window_includes_last_page(self):
        self.assertEqual(build_page_items(9, 10), [1, ELLIPSIS, 8, 9, 10])

    def test_middle_window_includes_last_page(self):
        self.assertEqual(
            build_page_items(5, 10),
            [1, ELLIPSIS, 4, 5, 6, ELLIPSIS, 10],
        )


if __name__ == '__main__':
    unittest.main()
