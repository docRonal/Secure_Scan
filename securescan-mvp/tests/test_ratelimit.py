"""Tests for the process-local sliding-window rate limiter."""
import time

import pytest

from app.ratelimit import SlidingWindowRateLimiter


def test_allows_requests_under_limit():
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        limiter.check("user-1")


def test_blocks_requests_over_limit():
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
    limiter.check("user-1")
    limiter.check("user-1")
    with pytest.raises(Exception) as exc_info:
        limiter.check("user-1")
    assert exc_info.value.status_code == 429


def test_limits_are_independent_per_key():
    limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=60)
    limiter.check("user-1")
    limiter.check("user-2")  # другой пользователь — свой собственный лимит


def test_old_hits_expire_out_of_window():
    limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=0.2)
    limiter.check("user-1")
    time.sleep(0.3)
    limiter.check("user-1")  # старое обращение уже вышло за окно — не должно бросить
