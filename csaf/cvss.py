"""CSAF CVSS 2/3.0/3.1 proxy implementation."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, Field

from csaf.vuln_types import (
    AccessComplexityType,
    AccessVectorType,
    AttackComplexityType,
    AttackVectorType,
    AuthenticationType,
    CiaRequirementType,
    CiaType,
    CollateralDamagePotentialType,
    ConfidenceType,
    ExploitabilityType,
    ExploitCodeMaturityType,
    ModifiedAttackComplexityType,
    ModifiedAttackVectorType,
    ModifiedCiaType,
    ModifiedPrivilegesRequiredType,
    ModifiedScopeType,
    ModifiedUserInteractionType,
    PrivilegesRequiredType,
    RemediationLevelType,
    ReportConfidenceType,
    ScopeType,
    TargetDistributionType,
    UserInteractionType,
)


class ScoreType(BaseModel):
    __root__: Annotated[float, Field(ge=0.0, le=10.0)]


class SeverityType(Enum):
    none = 'NONE'
    low = 'LOW'
    medium = 'MEDIUM'
    high = 'HIGH'
    critical = 'CRITICAL'


class Version(Enum):
    """
    CVSS Version
    """

    two = '2.0'
    three_zero = '3.0'
    three_wun = '3.1'


class CVSS2(BaseModel):
    version: Annotated[Version, Field(description='CVSS Version')] = Version.two
    vectorString: Annotated[
        str,
        Field(
            alias='vectorString',
            regex=(
                '^((AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:'
                '(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))/)*(AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:'
                '(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:'
                '(L|M|H|ND))$'
            ),
        ),
    ]
    accessVector: Annotated[Optional[AccessVectorType], Field(alias='accessVector')] = None
    accessComplexity: Annotated[Optional[AccessComplexityType], Field(alias='accessComplexity')] = None
    authentication: Optional[AuthenticationType] = None
    confidentialityImpact: Annotated[Optional[CiaType], Field(alias='confidentialityImpact')] = None
    integrityImpact: Annotated[Optional[CiaType], Field(alias='integrityImpact')] = None
    availabilityImpact: Annotated[Optional[CiaType], Field(alias='availabilityImpact')] = None
    baseScore: Annotated[ScoreType, Field(alias='baseScore')]
    exploitability: Optional[ExploitabilityType] = None
    remediationLevel: Annotated[Optional[RemediationLevelType], Field(alias='remediationLevel')] = None
    reportConfidence: Annotated[Optional[ReportConfidenceType], Field(alias='reportConfidence')] = None
    temporalScore: Annotated[Optional[ScoreType], Field(alias='temporalScore')] = None
    collateralDamagePotential: Annotated[
        Optional[CollateralDamagePotentialType],
        Field(alias='collateralDamagePotential'),
    ] = None
    targetDistribution: Annotated[Optional[TargetDistributionType], Field(alias='targetDistribution')] = None
    confidentialityRequirement: Annotated[
        Optional[CiaRequirementType], Field(alias='confidentialityRequirement')
    ] = None
    integrityRequirement: Annotated[Optional[CiaRequirementType], Field(alias='integrityRequirement')] = None
    availabilityRequirement: Annotated[Optional[CiaRequirementType], Field(alias='availabilityRequirement')] = None
    environmentalScore: Annotated[Optional[ScoreType], Field(alias='environmentalScore')] = None


class CVSS30(BaseModel):
    version: Annotated[Version, Field(description='CVSS Version')] = Version.three_zero
    vectorString: Annotated[
        str,
        Field(
            alias='vectorString',
            regex=(
                '^CVSS:3[.]0/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|'
                '[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|'
                'AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|'
                'MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$'
            ),
        ),
    ]
    attackVector: Annotated[Optional[AttackVectorType], Field(alias='attackVector')] = None
    attackComplexity: Annotated[Optional[AttackComplexityType], Field(alias='attackComplexity')] = None
    privilegesRequired: Annotated[Optional[PrivilegesRequiredType], Field(alias='privilegesRequired')] = None
    userInteraction: Annotated[Optional[UserInteractionType], Field(alias='userInteraction')] = None
    scope: Optional[ScopeType] = None
    confidentialityImpact: Annotated[Optional[CiaType], Field(alias='confidentialityImpact')] = None
    integrityImpact: Annotated[Optional[CiaType], Field(alias='integrityImpact')] = None
    availabilityImpact: Annotated[Optional[CiaType], Field(alias='availabilityImpact')] = None
    baseScore: Annotated[ScoreType, Field(alias='baseScore')]
    baseSeverity: Annotated[SeverityType, Field(alias='baseSeverity')]
    exploitCodeMaturity: Annotated[Optional[ExploitCodeMaturityType], Field(alias='exploitCodeMaturity')] = None
    remediationLevel: Annotated[Optional[RemediationLevelType], Field(alias='remediationLevel')] = None
    reportConfidence: Annotated[Optional[ConfidenceType], Field(alias='reportConfidence')] = None
    temporalScore: Annotated[Optional[ScoreType], Field(alias='temporalScore')] = None
    temporalSeverity: Annotated[Optional[SeverityType], Field(alias='temporalSeverity')] = None
    confidentialityRequirement: Annotated[
        Optional[CiaRequirementType], Field(alias='confidentialityRequirement')
    ] = None
    integrityRequirement: Annotated[Optional[CiaRequirementType], Field(alias='integrityRequirement')] = None
    availabilityRequirement: Annotated[Optional[CiaRequirementType], Field(alias='availabilityRequirement')] = None
    modifiedAttackVector: Annotated[Optional[ModifiedAttackVectorType], Field(alias='modifiedAttackVector')] = None
    modifiedAttackComplexity: Annotated[
        Optional[ModifiedAttackComplexityType], Field(alias='modifiedAttackComplexity')
    ] = None
    modifiedPrivilegesRequired: Annotated[
        Optional[ModifiedPrivilegesRequiredType],
        Field(alias='modifiedPrivilegesRequired'),
    ] = None
    modifiedUserInteraction: Annotated[
        Optional[ModifiedUserInteractionType], Field(alias='modifiedUserInteraction')
    ] = None
    modifiedScope: Annotated[Optional[ModifiedScopeType], Field(alias='modifiedScope')] = None
    modifiedConfidentialityImpact: Annotated[
        Optional[ModifiedCiaType], Field(alias='modifiedConfidentialityImpact')
    ] = None
    modifiedIntegrityImpact: Annotated[Optional[ModifiedCiaType], Field(alias='modifiedIntegrityImpact')] = None
    modifiedAvailabilityImpact: Annotated[
        Optional[ModifiedCiaType], Field(alias='modifiedAvailabilityImpact')
    ] = None
    environmentalScore: Annotated[Optional[ScoreType], Field(alias='environmentalScore')] = None
    environmentalSeverity: Annotated[Optional[SeverityType], Field(alias='environmentalSeverity')] = None


class CVSS31(BaseModel):
    version: Annotated[Version, Field(description='CVSS Version')] = Version.three_wun
    vectorString: Annotated[
        str,
        Field(
            alias='vectorString',
            regex=(
                '^CVSS:3[.]1/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:'
                '[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*'
                '(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:'
                '[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$'
            ),
        ),
    ]
    attackVector: Annotated[Optional[AttackVectorType], Field(alias='attackVector')] = None
    attackComplexity: Annotated[Optional[AttackComplexityType], Field(alias='attackComplexity')] = None
    privilegesRequired: Annotated[Optional[PrivilegesRequiredType], Field(alias='privilegesRequired')] = None
    userInteraction: Annotated[Optional[UserInteractionType], Field(alias='userInteraction')] = None
    scope: Optional[ScopeType] = None
    confidentialityImpact: Annotated[Optional[CiaType], Field(alias='confidentialityImpact')] = None
    integrityImpact: Annotated[Optional[CiaType], Field(alias='integrityImpact')] = None
    availabilityImpact: Annotated[Optional[CiaType], Field(alias='availabilityImpact')] = None
    baseScore: Annotated[ScoreType, Field(alias='baseScore')]
    baseSeverity: Annotated[SeverityType, Field(alias='baseSeverity')]
    exploitCodeMaturity: Annotated[Optional[ExploitCodeMaturityType], Field(alias='exploitCodeMaturity')] = None
    remediationLevel: Annotated[Optional[RemediationLevelType], Field(alias='remediationLevel')] = None
    reportConfidence: Annotated[Optional[ConfidenceType], Field(alias='reportConfidence')] = None
    temporalScore: Annotated[Optional[ScoreType], Field(alias='temporalScore')] = None
    temporalSeverity: Annotated[Optional[SeverityType], Field(alias='temporalSeverity')] = None
    confidentialityRequirement: Annotated[
        Optional[CiaRequirementType], Field(alias='confidentialityRequirement')
    ] = None
    integrityRequirement: Annotated[Optional[CiaRequirementType], Field(alias='integrityRequirement')] = None
    availabilityRequirement: Annotated[Optional[CiaRequirementType], Field(alias='availabilityRequirement')] = None
    modifiedAttackVector: Annotated[Optional[ModifiedAttackVectorType], Field(alias='modifiedAttackVector')] = None
    modifiedAttackComplexity: Annotated[
        Optional[ModifiedAttackComplexityType], Field(alias='modifiedAttackComplexity')
    ] = None
    modifiedPrivilegesRequired: Annotated[
        Optional[ModifiedPrivilegesRequiredType],
        Field(alias='modifiedPrivilegesRequired'),
    ] = None
    modifiedUserInteraction: Annotated[
        Optional[ModifiedUserInteractionType], Field(alias='modifiedUserInteraction')
    ] = None
    modifiedScope: Annotated[Optional[ModifiedScopeType], Field(alias='modifiedScope')] = None
    modifiedConfidentialityImpact: Annotated[
        Optional[ModifiedCiaType], Field(alias='modifiedConfidentialityImpact')
    ] = None
    modifiedIntegrityImpact: Annotated[Optional[ModifiedCiaType], Field(alias='modifiedIntegrityImpact')] = None
    modifiedAvailabilityImpact: Annotated[
        Optional[ModifiedCiaType], Field(alias='modifiedAvailabilityImpact')
    ] = None
    environmentalScore: Annotated[Optional[ScoreType], Field(alias='environmentalScore')] = None
    environmentalSeverity: Annotated[Optional[SeverityType], Field(alias='environmentalSeverity')] = None
