from django.shortcuts import redirect, render

from apps.core.permissions import audit, require_admin, require_viewer
from apps.targets.models import Target

from .forms import ScopeRuleForm
from .models import ScopeRule


@require_viewer
def scope_index(request):
    target_id = request.GET.get("target", "")
    qs = ScopeRule.objects.select_related("target").order_by("target__root_domain", "rule_type")
    if target_id:
        qs = qs.filter(target_id=target_id)
    return render(request, "scope/index.html",
                  {"rules": qs, "targets": Target.objects.all(), "target_id": target_id})


@require_admin
def scope_add(request):
    if request.method == "POST":
        form = ScopeRuleForm(request.POST)
        if form.is_valid():
            rule = form.save(commit=False)
            rule.created_by = request.user
            rule.save()
            from services.event_engine.engine import emit_event

            emit_event("SCOPE_CHANGED", target=rule.target, asset_value=rule.value,
                       source="scope-ui",
                       evidence={"action": "added", "rule_type": rule.rule_type, "value": rule.value,
                                 "actor": request.user.username})
            audit(request, "scope.changed", rule, new=f"+{rule.rule_type}={rule.value}")
            return redirect("scope-index")
    else:
        form = ScopeRuleForm()
    return render(request, "scope/form.html", {"form": form})


@require_admin
def scope_delete(request, pk):
    from django.shortcuts import get_object_or_404

    rule = get_object_or_404(ScopeRule, pk=pk)
    if request.method == "POST":
        from services.event_engine.engine import emit_event

        emit_event("SCOPE_CHANGED", target=rule.target, asset_value=rule.value,
                   source="scope-ui",
                   evidence={"action": "removed", "rule_type": rule.rule_type, "value": rule.value,
                             "actor": request.user.username})
        audit(request, "scope.changed", rule, old=f"-{rule.rule_type}={rule.value}")
        rule.delete()
        return redirect("scope-index")
    return render(request, "scope/confirm_delete.html", {"rule": rule})
