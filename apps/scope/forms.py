from django import forms

from .models import ScopeRule


class ScopeRuleForm(forms.ModelForm):
    class Meta:
        model = ScopeRule
        fields = ["target", "rule_type", "value"]
