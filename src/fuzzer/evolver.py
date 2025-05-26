#!/usr/bin/env python3
import random

def fit_pool(core, corpus, trace_global, pool, target_size=100):
    # Core orig + novedades + relleno de mayor a menor
    pool.clear()

    for sample in core:
        pool.append((sample, set()))

    for sample, trace in corpus:
        if trace - trace_global:
            pool.append((sample, trace))

    if corpus and len(pool) < target_size:
        corpus.sort(key=lambda x: len(x[1]), reverse=True)
        needed = target_size - len(pool)
        for _ in range(min(needed, len(corpus))):
            v = int(random.random() * random.random() * len(corpus))
            pool.append(corpus.pop(v))

    for _, t in corpus:
        trace_global |= t
    corpus.clear()


def mutate_pool(pool, samples, mutators, multiplier=10):
    samples.clear()
    while pool:
        sample, _ = pool.pop()
        for _ in range(multiplier):
            idx = random.randrange(len(mutators))
            f = mutators[idx]
            mutated = f(bytearray(sample))
            samples.append((mutated, idx))
