"""Conservative HTTP directory-enumeration evidence from completed windows."""


def is_directory_enumeration(
    *, request_count: int, unique_paths: float, top_path_share: float,
    request_rate: float, peak_second_requests: float,
) -> bool:
    """Flag fast, broad path probing, including sites that rewrite misses to HTTP 200."""
    return (
        request_count >= 120
        and unique_paths >= 80
        and unique_paths / request_count >= 0.7
        and top_path_share <= 0.1
        and (request_rate >= 2.0 or peak_second_requests >= 10)
    )
