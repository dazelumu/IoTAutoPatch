"""Firmware automatic-repair pipeline (0.2.0).

Generic controller: rehost a firmware image, confirm a fault from runtime
exit evidence, let a model investigate via bounded evidence queries, generate
and implant a repair, then verify the candidate. Device specifics live in
adapters/, CPU specifics in ../arch/. No device hashes, addresses or buffer
sizes are hardcoded here.
"""
