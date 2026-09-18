from fraud.engine import FraudEngine

engine = FraudEngine()

print("=== Test 1: Petit montant (risque faible) ===")
r = engine.analyze(50.0, "EUR", "tok_test", "MERCH_001", "192.168.1.1")
print(f"  Score: {r['risk_score']} | Niveau: {r['risk_level']} | Decision: {r['recommendation']}")

print("\n=== Test 2: Montant eleve (risque moyen) ===")
r = engine.analyze(7500.0, "EUR", "tok_test", "MERCH_001", "192.168.1.1")
print(f"  Score: {r['risk_score']} | Niveau: {r['risk_level']} | Decision: {r['recommendation']}")
print(f"  Flags: {r['flags']}")

print("\n=== Test 3: Montant tres eleve (risque critique) ===")
r = engine.analyze(15000.0, "EUR", "tok_test", "MERCH_001", "192.168.1.1")
print(f"  Score: {r['risk_score']} | Niveau: {r['risk_level']} | Decision: {r['recommendation']}")

print("\n=== Test 4: IP manquante (risque leger) ===")
r = engine.analyze(100.0, "EUR", "tok_test", "MERCH_001", "")
print(f"  Score: {r['risk_score']} | Flags: {r['flags']}")

print("\nTOURNE OK !")
