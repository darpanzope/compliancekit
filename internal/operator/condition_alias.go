package operator

// Local alias for metav1.Condition keeps the deepcopy.go file
// compact + avoids a circular reference back to apimachinery in
// the per-type DeepCopy helpers.

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type metaCondition = metav1.Condition
