import json
from django.core.management.base import BaseCommand, CommandError
from apps.media_library.storage_archive import eligible_originals, archive_asset


class Command(BaseCommand):
    help = "List confirmed original candidates; --execute archives and --retire evicts verified originals."

    def add_arguments(self, parser):
        parser.add_argument("--confirmations", required=True)
        parser.add_argument("--workspace", default="99d7934b-9a92-442c-9414-80bc088a36b5")
        parser.add_argument("--minimum-bytes", type=int, default=1)
        parser.add_argument("--limit", type=int, default=10)
        parser.add_argument("--max-bytes", type=int, default=0)
        parser.add_argument("--asset", action="append", default=[])
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--retire", action="store_true")

    def handle(self, *args, **options):
        if options["retire"] and not options["execute"]:
            raise CommandError("--retire requires --execute")
        if options["limit"] < 1 or options["minimum_bytes"] < 1:
            raise CommandError("positive limit and minimum-bytes required")
        selected = set(options["asset"])
        count = 0
        selected_bytes = 0
        if options["max_bytes"] < 0:
            raise CommandError("max-bytes must be nonnegative")
        for asset in eligible_originals(options["confirmations"], options["minimum_bytes"], options["workspace"]):
            if selected and str(asset.pk) not in selected:
                continue
            if options["max_bytes"] and selected_bytes + asset.file_size > options["max_bytes"]:
                continue
            result = {"asset_id": str(asset.pk), "storage_key": asset.file.name, "bytes": asset.file_size, "action": "candidate"}
            if options["execute"]:
                record = archive_asset(asset.pk, options["confirmations"], retire_original=options["retire"])
                result.update(action="retired" if record.get("resident_state") == "ABSENT" else "archived", archive=record)
            self.stdout.write(json.dumps(result))
            count += 1
            selected_bytes += asset.file_size
            if count >= options["limit"]:
                break
        self.stdout.write(json.dumps({"selected": count, "executed": options["execute"]}))
