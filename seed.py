from app.database import SessionLocal, engine, Base
from app.models import Application


APPS = [
    "orgmorg",
    "orgmcalc",
    "orgmcalc-cli",
    "orgmbt",
    "orgmbt-cli",
    "orgmbt-app",
    "orgmrnc",
]


def seed_applications():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        for app_name in APPS:
            existing = (
                db.query(Application).filter(Application.name == app_name).first()
            )
            if not existing:
                app = Application(name=app_name)
                db.add(app)
                print(f"Added: {app_name}")

        db.commit()
        print("Seed completed!")

        apps = db.query(Application).order_by(Application.name).all()
        print(f"\nTotal applications: {len(apps)}")
        for app in apps:
            print(f"  - {app.name}")

    finally:
        db.close()


if __name__ == "__main__":
    seed_applications()
