# Static Program Analysis - SPL

## Core Concepts

### Sound, Truth, and Complete

| Term         | Definition                                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------- |
| **Truth**    | The actual set of facts that hold in program execution (ground truth)                                               |
| **Sound**    | An analysis is sound if it reports all actual issues (over-approximation). If truth ⊆ reported, then sound.         |
| **Complete** | An analysis is complete if everything it reports is true (under-approximation). If reported ⊆ truth, then complete. |

```
Sound:     Truth ⊆ Reported   (no false negatives, may have false positives)
Complete:  Reported ⊆ Truth   (no false positives, may have false negatives)
```

### False Positives & False Negatives

| Term                    | Definition                                 | Caused by                               |
| ----------------------- | ------------------------------------------ | --------------------------------------- |
| **False Positive (FP)** | Reported issue that doesn't actually exist | Over-approximation (sound analysis)     |
| **False Negative (FN)** | Actual issue that was not reported         | Under-approximation (complete analysis) |

```
                    Actual Issue?
                    Yes         No
Reported?  Yes      True +      False + (FP)
           No       False - (FN) True -
```

### Useful Static Analysis

Rice's Theorem states: Any non-trivial semantic property of programs is undecidable.

Therefore, perfect static analysis (both sound AND complete) is impossible for non-trivial properties.

**Practical trade-off:**

| Analysis Type          | Sound | Complete | False Positives | False Negatives | Use Case                         |
| ---------------------- | ----- | -------- | --------------- | --------------- | -------------------------------- |
| Sound but not complete | Yes   | No       | Yes             | No              | Security analysis (miss nothing) |
| Complete but not sound | No    | Yes      | No              | Yes             | Bug finding (high confidence)    |

**Useful static analysis = Sound + Low false positive rate**

Most practical tools compromise:

- Soundness ensures no real bugs are missed
- Precision techniques reduce false positives to acceptable levels

```
Soundness is critical → missing real bugs is dangerous
Completeness sacrificed → tolerate some false alarms
```

## Reference

- [software analysis intro - nanjing university](https://cs.nju.edu.cn/tiantan/software-analysis/introduction.pdf)
