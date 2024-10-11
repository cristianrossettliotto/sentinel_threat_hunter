#include "pch.h"
#include "controls.h"

VOID FreeObjects() {
	for (int i = 0; i < TECHNIQUES_BUFFER_SIZE; i++)
		if (Techniques[i])
			free(Techniques[i]);
}

VOID TerminateCurrentProcess() {
	printf("\t\n\n-----------------------------------------------------------------------------\n");
	printf("\t\t[::] Due to malicious behavior the DLL is terminating the current process!\n");
	printf("\t\n\n-----------------------------------------------------------------------------\n");
	TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
}

BOOL GetNewTechniquePerforming(TECHNIQUEPERFORMING** Technique) {
	if (!Technique)
		return FALSE;

	for (int i = 0; i < TECHNIQUES_BUFFER_SIZE; i++)
		if (Techniques[i] == NULL)
			*Technique = Techniques[i] = (TECHNIQUEPERFORMING*)calloc(1, sizeof(TECHNIQUEPERFORMING));

	if (!*Technique)
		return FALSE;

	return TRUE;
}

BOOL FindTechniquePerformingByTargetHandle(TECHNIQUEPERFORMING** Technique, HANDLE hTarget) {
	if (!Technique || !hTarget)
		return FALSE;

	for (int i = 0; i < TECHNIQUES_BUFFER_SIZE; i++)
		if (Techniques[i] && Techniques[i]->hTarget == hTarget) {
			*Technique = Techniques[i];
			break;
		}

	if (*Technique)
		return TRUE;

	return FALSE;
}

BOOL FindTechniquePerformingByTargetAddress(TECHNIQUEPERFORMING** Technique, LPVOID lpAddressTarget) {
	if (!Technique || !lpAddressTarget)
		return FALSE;

	for (int i = 0; i < TECHNIQUES_BUFFER_SIZE; i++)
		if (Techniques[i] && (Techniques[i]->lpAddressTarget == lpAddressTarget || (((DWORD)Techniques[i]->lpAddressTarget) - ((DWORD)lpAddressTarget) <= 0x500))) {
			*Technique = Techniques[i];
			break;
		}

	if (*Technique)
		return TRUE;

	return FALSE;
}

BOOL FindTechniquePerformingByStepPerformed(TECHNIQUEPERFORMING** Technique, UINT StepPerformed) {
	if (!Technique || !StepPerformed)
		return FALSE;

	for (int i = 0; i < TECHNIQUES_BUFFER_SIZE; i++)
		if (Techniques[i] && Techniques[i]->ucTechniquesFlags & StepPerformed) {
			*Technique = Techniques[i];
			break;
		}

	if (*Technique)
		return TRUE;

	return FALSE;
}