#pragma once

#include "pch.h"
#include "definitions.h"

#define ENCRYPTION_THRESHOLD 3
#define INVALID_CHARACTER_THRESHOLD 20

VOID FreeObjects();
BOOL GetNewTechniquePerforming(TECHNIQUEPERFORMING** Technique);
BOOL FindTechniquePerformingByTargetHandle(TECHNIQUEPERFORMING** Technique, HANDLE hTarget);
BOOL FindTechniquePerformingByTargetAddress(TECHNIQUEPERFORMING** Technique, LPVOID lpAddressTarget);
BOOL FindTechniquePerformingByStepPerformed(TECHNIQUEPERFORMING** Technique, UINT StepPerformed);
VOID TerminateCurrentProcess();